const express = require('express');
const sql = require('mssql');

const cors = require('cors');
require('dotenv').config();
const app = express();
const PORT = process.env.PORT || 3000;  // Dinamik port tanımlaması


app.use(cors());
app.use(express.json());

const connectionPools = new Map(); // Bağlantı havuzları için bir Map

// Bağlantı havuzu almak için yardımcı fonksiyon
async function getConnectionPool(config) {
    const cacheKey = `${config.user}@${config.server}:${config.port}/${config.database}`;
    
    if (connectionPools.has(cacheKey)) {
        // Bağlantı havuzu zaten var
        return connectionPools.get(cacheKey);
    } else {
        // Yeni bir bağlantı havuzu oluştur
        const pool = new sql.ConnectionPool(config);
        await pool.connect();
        connectionPools.set(cacheKey, pool);
        return pool;
    }
}
function isValidDate(dateString) {
    const regex = /^\d{2}\.\d{2}\.\d{4}$/; // DD.MM.YYYY formatı
    if (!dateString.match(regex)) {
        return false;
    }

    const [day, month, year] = dateString.split('.').map(Number);
    const date = new Date(year, month - 1, day);

    // Günün geçerli olup olmadığını kontrol et
    return date.getFullYear() === year &&
           date.getMonth() === month - 1 &&
           date.getDate() === day;
}

function formatDate(dateString) {
    const [day, month, year] = dateString.split('.').map(Number);
    return `${year}-${month.toString().padStart(2, '0')}-${day.toString().padStart(2, '0')}`;
}
function base64Encode(data) {
    return Buffer.from(data).toString('base64');
}

app.post('/login', async (req, res) => {
    const { username, userPassword,  } = req.body;
    console.log('Gelen veri :', req.body);

    // Gerekli alanların kontrolü
    if ( !username || !userPassword) {
        return res.status(400).send('Eksik alanlar var');
    }

    const encodedUserPassword = base64Encode(userPassword); 
    console.log(encodedUserPassword)
    // MSSQL bağlantı ayarları
    const config = {
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        server: process.env.DB_SERVER,
        database: process.env.DB_DATABASE,
        options: {
            encrypt: false, 
            trustServerCertificate: true,
            connectTimeout: 30000 
        }
    };

    try {
        const pool = await getConnectionPool(config);

        // İlk SQL sorgusu (Kullanıcı bilgilerini bulma)
        const userResult = await pool.request()
            .input('username', sql.VarChar, username)
            .input('userPassword', sql.VarChar, encodedUserPassword)
            .query(`
                SELECT TOP (1) Id, UserName, Sifre, UserStatus, StartDate, FinishDate, mobil, ADI_SOYADI
                FROM dbo.Users
                WHERE UserName = @username  AND Sifre = @userPassword
            `);

        if (userResult.recordset.length > 0) {
            const user = userResult.recordset[0];
            const userId = user.Id;

            console.log('Kullanıcı bulundu:', user);

            // FinishDate kontrolü (Kullanım süresi dolmuş mu?)
            const today = new Date();
            const finishDate = new Date(user.FinishDate);

            if (finishDate < today) {
                return res.status(404).send('Kullanım süresi dolmuştur');
            }

            // Kullanıcının şube bilgilerini sorgulama
            const userSubeResult = await pool.request()
                .input('userId', sql.Int, userId)
                .query(`
                    SELECT 
                        us.UserSube_ID,
                        us.User_Id,
                        us.Sube_Id,
                        s.Sube,
                        s.ServerName,
                        s.ServerDatabaseName,
                        s.ServerUserName,
                        s.ServerUserPassWord,
                        s.LOCAL_WEB_ADRES,
                        s.PORT_SERVIS
                    FROM 
                        dbo.UserSube us
                    JOIN 
                        dbo.Sube s ON us.Sube_Id = s.Sube_ID
                    WHERE 
                        us.User_Id = @userId;  
                `);

            if (userSubeResult.recordset.length > 0) {
                res.json({
                    user: userResult.recordset[0],
                    userSube: userSubeResult.recordset
                });
            } else {
                console.log('Kullanıcı şube bilgileri bulunamadı');
                res.status(404).send('Kullanıcı şube bilgileri bulunamadı');
            }
        } else {
            console.log('Kullanıcı bulunamadı');
            res.status(404).send('Kullanıcı bulunamadı');
        }
    } catch (err) {
        console.error('Veritabanı sorgu hatası:', err);
        res.status(500).send('Veritabanı sorgusu başarısız');
    }
});

app.post('/changePassword', async (req, res) => {
    const { username, newPassword, user, password, hostAddress, dbName } = req.body;
    console.log('Gelen veri :', req.body);

    // Gerekli alanların kontrolü
    if (!username || !newPassword || !user || !password || !hostAddress || !dbName) {
        return res.status(400).send('Eksik alanlar var');
    }
    const encodedUserPassword = base64Encode(newPassword); 
    console.log(encodedUserPassword);
    // MSSQL bağlantı ayarları
    const config = {
        user: user,
        password: password,
        server: hostAddress,
        database: dbName,
        options: {
            encrypt: false, 
            trustServerCertificate: true,
            connectTimeout: 30000 
        }
    };

    try {
        const pool = await getConnectionPool(config);

        // Kullanıcıyı bul ve şifreyi güncelle
        const updatePasswordResult = await pool.request()
            .input('username', sql.VarChar, username)
            .input('newPassword', sql.VarChar, encodedUserPassword)
            .query(`
                UPDATE dbo.Users
                SET Sifre = @newPassword
                WHERE UserName = @username
            `);

        if (updatePasswordResult.rowsAffected[0] > 0) {
            console.log('Şifre başarıyla güncellendi');
            res.status(200).send('Şifre başarıyla güncellendi');
        } else {
            console.log('Kullanıcı bulunamadı veya şifre güncellenemedi');
            res.status(404).send('Kullanıcı bulunamadı veya şifre güncellenemedi');
        }
    } catch (err) {
        console.error('Veritabanı sorgu hatası:', err);
        res.status(500).send('Veritabanı sorgusu başarısız');
    }
});

app.post('/cekler_ve_toplam', async (req, res) => {
    const { user, password, hostAddress, port, dbName } = req.body;
    console.log(req.body);

    // Gerekli alanlar var mı kontrol et
    if (!user || !password || !hostAddress || !port || !dbName) {
        return res.status(400).send('Missing required fields');
    }

    // Şifreyi decode et (base64 kodlama varsayılarak)
    const encodedUserPassword = decodeBase64(password);
    console.log(encodedUserPassword);

    const config = {
        user: user,
        password: encodedUserPassword,
        server: hostAddress,
        port: port,
        database: dbName,
        options: {
            encrypt: false, // SQL Server SSL kullanıyorsanız
            trustServerCertificate: true ,// Sertifikaları kontrol ederek bağlan

        }
    };

    // Bugünkü tarih için formatlama fonksiyonu
    const getCurrentDate = () => {
        const today = new Date();
        return today.toISOString().split('T')[0]; // YYYY-MM-DD formatı
    };
    const currentDate = getCurrentDate();

    try {
        // Bağlantı havuzunu al
        const pool = await getConnectionPool(config);

        // Tek bir sorgu ile sonuçları al
        const result = await pool.request().query(`
            SELECT 
              ISNULL((SELECT SUM(SFIY * MIKTAR) 
               FROM RESCEK), 0.00) AS ACIK_MASALAR,
              
              ISNULL((SELECT SUM(SFIY * MIKTAR) 
               FROM RESHRY 
               WHERE CONVERT(DATE, TARIH, 120) >= '${currentDate}' 
                 AND CONVERT(DATE, TARIH, 120) <= '${currentDate}'), 0.00) AS KAPALI_MASALAR,
              
              ISNULL((SELECT SUM(SFIY * MIKTAR) 
               FROM RESIPT 
               WHERE CONVERT(DATE, TARIH, 120) >= '${currentDate}' 
                 AND CONVERT(DATE, TARIH, 120) <= '${currentDate}'), 0.00) AS IPTAL_MASALAR,
              
              ISNULL((SELECT SUM(ISKONTOTUTARI1) 
               FROM RESHRY 
               WHERE CONVERT(DATE, TARIH, 120) >='${currentDate}' 
                 AND CONVERT(DATE, TARIH, 120) <= '${currentDate}'), 0.00) AS ISKONTO,
              
              ISNULL((SELECT SUM(ALACAK) 
               FROM KASHRY 
               WHERE CONVERT(DATE, TARIH, 120) >= '${currentDate}' 
                 AND CONVERT(DATE, TARIH, 120) <= '${currentDate}'), 0.00) AS MASRAFLAR;
        `);

        // Sonuçları al ve toplam hesapla
        const { ACIK_MASALAR, KAPALI_MASALAR, IPTAL_MASALAR, ISKONTO, MASRAFLAR } = result.recordset[0];
        const Toplam = parseFloat(ACIK_MASALAR) + parseFloat(KAPALI_MASALAR)  - parseFloat(ISKONTO) ;

        // Sonuçları döndür
        res.json({
            ACIK_MASALAR,
            KAPALI_MASALAR,
            IPTAL_MASALAR,
            ISKONTO,
            MASRAFLAR,
            Toplam: Toplam.toFixed(2) // Toplamı 2 ondalıklı olarak döndür
        });
    } catch (err) {
        console.error('Database query error:', {
            name: err.name,
            message: err.message,
            stack: err.stack,
            code: err.code,
            detail: err.detail
        });
        res.status(500).send('Database query failed: ' + err.message);
    }
});



function decodeBase64(encodedMessage) {
    // Base64 ile şifrelenmiş metni normal metne çevir
    const decodedMessage = Buffer.from(encodedMessage, 'base64').toString('utf-8');
    return decodedMessage;
}
app.post('/urun_satis_detayi_miktaragore', async (req, res) => { 
    const { user, password, hostAddress, port, dbName, trhb, trhs } = req.body;
    console.log(req.body);
    if (!user || !password || !hostAddress || !port || !dbName || !trhb || !trhs) {
        return res.status(400).send('Missing required fields');
    }

    // Tarih formatlarını kontrol et
    if (!isValidDate(trhb) || !isValidDate(trhs)) {
        return res.status(400).send('Invalid date format');
    }

    const encodedUserPassword = decodeBase64(password); 
    console.log(encodedUserPassword);
    
    const startDate = formatDate(trhb);
    const endDate = formatDate(trhs);
    
    const config = {
        user: user,
        password: encodedUserPassword,
        server: hostAddress,
        port: port,
        database: dbName,
        options: {
            encrypt: false, // SQL Server SSL kullanıyorsanız
            trustServerCertificate: true // Sertifikaları kontrol ederek bağlan
        }
    };
         console.log(config);
    try {
        // Bağlantı havuzunu al
        const pool = await getConnectionPool(config);
        
        // Sorguyu çalıştır
        const result = await pool.request().query(`
            SET DATEFORMAT DMY;
            SELECT TOP 1000 
                KOD, 
                ACIKLAMA, 
                YEMEK_KODU, 
                YEMEK_ADI, 
                STR(ROUND(CONVERT(FLOAT, SUM(MIKTAR)), 2), 12, 2) AS MIKTAR, 
                STR(ROUND(CONVERT(FLOAT, SUM(SFIY)), 2), 12, 2) AS SFIY, 
                STR(ROUND(CONVERT(FLOAT, SUM(ISKONTO)), 2), 12, 2) AS ISKONTO,  
                STR(ROUND(CONVERT(FLOAT, SUM(NET_TUTAR)), 2), 12, 2) AS NET_TUTAR
            FROM 
            (
                SELECT 
                    KOD, 
                    ACIKLAMA,
                    YEMEK_KODU1 AS YEMEK_KODU, 
                    YEMEK_ADI1 AS YEMEK_ADI, 
                    ROUND(CONVERT(FLOAT, SUM(MIKTAR)), 2) AS MIKTAR, 
                    ROUND(CONVERT(FLOAT, SUM(SFIY)), 2) AS SFIY, 
                    ROUND(CONVERT(FLOAT, SUM(ISKONTO)), 2) AS ISKONTO,  
                    ROUND(CONVERT(FLOAT, SUM(NET_TUTAR)), 2) AS NET_TUTAR 
                FROM 
                (
                    SELECT  
                        H.STOKKODU AS KOD, 
                        M.STOKADI AS ACIKLAMA, 
                        M.YEMEK_KODU1, 
                        DBO.FNC_RES_ANAYEMEKADI(M.YEMEK_KODU1) AS YEMEK_ADI1,   
                        SUM(MIKTAR) AS MIKTAR, 
                        SUM(H.MIKTAR * H.SFIY) AS SFIY, 
                        SUM(H.ISKONTOTUTARI) AS ISKONTO,   
                        SUM(ISNULL((H.SFIY * H.MIKTAR), 0) - ISNULL(ISKONTOTUTARI, 0)) AS NET_TUTAR   
                    FROM RESHRY AS H 
                    INNER JOIN STKMAS AS M ON (H.STOKKODU = M.STOKKODU)    
                    WHERE 
                        H.TARIH BETWEEN CAST(CONVERT(DATETIME, '${startDate}', 120) AS DATETIME) 
                                    AND CAST(CONVERT(DATETIME, '${endDate}', 120) AS DATETIME) 
                        AND H.KOD = 'B'  
                    GROUP BY 
                        H.STOKKODU, 
                        M.STOKADI, 
                        M.YEMEK_KODU1
                ) AS SONTABLO    
                GROUP BY 
                    KOD, 
                    ACIKLAMA,
                    YEMEK_KODU1, 
                    YEMEK_ADI1  
                UNION ALL
                SELECT 
                    KOD, 
                    ACIKLAMA,
                    YEMEK_KODU1 AS YEMEK_KODU, 
                    YEMEK_ADI1 AS YEMEK_ADI, 
                    ROUND(CONVERT(FLOAT, SUM(MIKTAR)), 2) AS MIKTAR, 
                    ROUND(CONVERT(FLOAT, SUM(SFIY)), 2) AS SFIY, 
                    ROUND(CONVERT(FLOAT, SUM(ISKONTO)), 2) AS ISKONTO,  
                    ROUND(CONVERT(FLOAT, SUM(NET_TUTAR)), 2) AS NET_TUTAR 
                FROM 
                (
                    SELECT  
                        H.STOKKODU AS KOD, 
                        M.STOKADI AS ACIKLAMA, 
                        M.YEMEK_KODU1, 
                        DBO.FNC_RES_ANAYEMEKADI(M.YEMEK_KODU1) AS YEMEK_ADI1,   
                        SUM(MIKTAR) AS MIKTAR, 
                        SUM(H.MIKTAR * H.SFIY) AS SFIY, 
                        SUM(H.ISKONTOTUTARI) AS ISKONTO,   
                        SUM(ISNULL((H.SFIY * H.MIKTAR), 0) - ISNULL(ISKONTOTUTARI, 0)) AS NET_TUTAR   
                    FROM RESCEK AS H 
                    INNER JOIN STKMAS AS M ON (H.STOKKODU = M.STOKKODU)    
                    WHERE 
                        H.TARIH BETWEEN CAST(CONVERT(DATETIME, '${startDate}', 120) AS DATETIME) 
                                    AND CAST(CONVERT(DATETIME, '${endDate}', 120) AS DATETIME) 
                        AND H.KOD = 'B'  
                    GROUP BY 
                        H.STOKKODU, 
                        M.STOKADI, 
                        M.YEMEK_KODU1
                ) AS SONTABLO    
                GROUP BY 
                    KOD, 
                    ACIKLAMA,
                    YEMEK_KODU1, 
                    YEMEK_ADI1
            ) AS ENSONTABLO 
            GROUP BY 
                KOD, 
                ACIKLAMA,
                YEMEK_KODU, 
                YEMEK_ADI  
            ORDER BY MIKTAR DESC;
        `);
        
        // Sonuçları döndür
        res.json(result.recordset);
    } catch (err) {
        console.error('Database query error:', {
            name: err.name,
            message: err.message,
            stack: err.stack,
            code: err.code, // Hata kodunu ekleyebilirsiniz
            detail: err.detail // Eğer varsa hata detayını ekleyebilirsiniz
        });
        res.status(500).send('Database query failed: ' + err.message);
    }
});






app.post('/urun_satis_detayi', async (req, res) => {
    const { user, password, hostAddress, port, dbName, trhb, trhs } = req.body;
    console.log(req.body);
    if (!user || !password || !hostAddress  || !dbName || !trhb || !trhs) {
        return res.status(400).send('Parametreler eksik.');
    }

    // Tarih formatlarını kontrol et
    if (!isValidDate(trhb) || !isValidDate(trhs)) {
        return res.status(400).send('Geçersiz tarih formatı.');
    }
    const encodedUserPassword = decodeBase64(password); 
    console.log(encodedUserPassword);
    const startDate = formatDate(trhb);
    const endDate = formatDate(trhs);

    const config = {
        user: user,
        password: encodedUserPassword,
        server: hostAddress,
        port: parseInt(port),
        database: dbName,
        options: {
            encrypt: false,
            trustServerCertificate: true
        }
    };

    try {
        const pool = await getConnectionPool(config);
        
        // Sorguyu çalıştır
        const result = await pool.request().query(`
            SET DATEFORMAT ymd;
            SELECT TOP 1000 KOD, ACIKLAMA, YEMEK_KODU, YEMEK_ADI,
            Str(round(convert(float,SUM(MIKTAR)),2), 12, 2) AS MIKTAR,
            Str(round(convert(float,SUM(SFIY)),2), 12, 2) AS SFIY,
            Str(round(convert(float,SUM(ISKONTO)),2), 12, 2) AS ISKONTO,
            Str(round(convert(float,SUM(NET_TUTAR)),2), 12, 2) AS NET_TUTAR
            FROM 
            (SELECT KOD, ACIKLAMA, YEMEK_KODU1 AS YEMEK_KODU, YEMEK_ADI1 AS YEMEK_ADI,
            round(convert(float,SUM(MIKTAR)),2) AS MIKTAR,
            round(convert(float,SUM(SFIY)),2) AS SFIY,
            round(convert(float,SUM(ISKONTO)),2) AS ISKONTO,
            round(convert(float,SUM(NET_TUTAR)),2) AS NET_TUTAR 
            FROM (
                SELECT H.STOKKODU AS KOD, M.STOKADI AS ACIKLAMA, M.YEMEK_KODU1, DBO.FNC_RES_ANAYEMEKADI(M.YEMEK_KODU1) AS YEMEK_ADI1,
                SUM(MIKTAR) AS MIKTAR,
                SUM(H.MIKTAR*H.SFIY) AS SFIY,
                SUM(H.ISKONTOTUTARI) AS ISKONTO,
                SUM(ISNULL((H.SFIY*H.MIKTAR),0)-ISNULL(ISKONTOTUTARI,0)) AS NET_TUTAR
                FROM RESHRY AS H
                INNER JOIN STKMAS AS M ON (H.STOKKODU = M.STOKKODU)
                WHERE H.TARIH BETWEEN '${startDate} 00:00:00' 
                AND '${endDate} 23:59:59'
                AND H.KOD = 'B'
                GROUP BY H.STOKKODU, M.STOKADI, M.YEMEK_KODU1
            ) AS SONTABLO
            GROUP BY KOD, ACIKLAMA, YEMEK_KODU1, YEMEK_ADI1
            UNION ALL
            SELECT KOD, ACIKLAMA, YEMEK_KODU1 AS YEMEK_KODU, YEMEK_ADI1 AS YEMEK_ADI,
            round(convert(float,SUM(MIKTAR)),2) AS MIKTAR,
            round(convert(float,SUM(SFIY)),2) AS SFIY,
            round(convert(float,SUM(ISKONTO)),2) AS ISKONTO,
            round(convert(float,SUM(NET_TUTAR)),2) AS NET_TUTAR 
            FROM (
                SELECT H.STOKKODU AS KOD, M.STOKADI AS ACIKLAMA, M.YEMEK_KODU1, DBO.FNC_RES_ANAYEMEKADI(M.YEMEK_KODU1) AS YEMEK_ADI1,
                SUM(MIKTAR) AS MIKTAR,
                SUM(H.MIKTAR*H.SFIY) AS SFIY,
                SUM(H.ISKONTOTUTARI) AS ISKONTO,
                SUM(ISNULL((H.SFIY*H.MIKTAR),0)-ISNULL(ISKONTOTUTARI,0)) AS NET_TUTAR
                FROM RESCEK AS H
                INNER JOIN STKMAS AS M ON (H.STOKKODU = M.STOKKODU)
                WHERE H.TARIH BETWEEN '${startDate} 00:00:00'
                AND '${endDate} 23:59:59'
                AND H.KOD = 'B'
                GROUP BY H.STOKKODU, M.STOKADI, M.YEMEK_KODU1
            ) AS SONTABLO
            GROUP BY KOD, ACIKLAMA, YEMEK_KODU1, YEMEK_ADI1
            ) AS ENSONTABLO
            GROUP BY KOD, ACIKLAMA, YEMEK_KODU, YEMEK_ADI
            ORDER BY NET_TUTAR DESC;
        `);


        res.json(result.recordset);
    } catch (err) {
        console.error('SQL sorgu hatası:', err);
        res.status(500).send('Veriler çekilemedi.');
    } 
});



//BU SORGUDA NEDEN TARİH YOK SOR ONU
app.post('/urun_satis_acik', async (req, res) => {
    const { user, password, hostAddress, port, dbName, trhb, trhs } = req.body;
    if (!user || !password || !hostAddress || !port || !dbName || !trhb || !trhs) {
        return res.status(400).send('Parametreler eksik.');
    }

    // Tarih formatlarını kontrol et
    if (!isValidDate(trhb) || !isValidDate(trhs)) {
        return res.status(400).send('Geçersiz tarih formatı.');
    }
    const encodedUserPassword = decodeBase64(password); 
    console.log(encodedUserPassword);
    const startDate = formatDate(trhb);
    const endDate = formatDate(trhs);

    const config = {
        user: user,
        password: encodedUserPassword,
        server: hostAddress,
        port: parseInt(port),
        database: dbName,
        options: {
            encrypt: false,
            trustServerCertificate: true
        }
    };

    try {
        const pool = await getConnectionPool(config);
        
        // Sorguyu çalıştır
        const result = await pool.request().query(`
            SET DATEFORMAT dmy;
            SELECT TOP 1000 KOD, ACIKLAMA, YEMEK_KODU1 AS YEMEK_KODU, YEMEK_ADI1 AS YEMEK_ADI, 
            Str(round(convert(float, SUM(MIKTAR)), 2), 12, 2) AS MIKTAR, 
            Str(round(convert(float, SUM(SFIY)), 2), 12, 2) AS SFIY, 
            Str(round(convert(float, SUM(ISKONTO)), 2), 12, 2) AS ISKONTO,  
            Str(round(convert(float, SUM(NET_TUTAR)), 2), 12, 2) AS NET_TUTAR 
            FROM (
                SELECT H.STOKKODU AS KOD, M.STOKADI AS ACIKLAMA, M.YEMEK_KODU1, DBO.FNC_RES_ANAYEMEKADI(M.YEMEK_KODU1) AS YEMEK_ADI1,
                SUM(MIKTAR) AS MIKTAR,
                SUM(H.MIKTAR * H.SFIY) AS SFIY,
                SUM(H.ISKONTOTUTARI) AS ISKONTO,
                SUM(ISNULL((H.SFIY * H.MIKTAR), 0) - ISNULL(ISKONTOTUTARI, 0)) AS NET_TUTAR
                FROM RESCEK AS H
                INNER JOIN STKMAS AS M ON (H.STOKKODU = M.STOKKODU)
                GROUP BY H.STOKKODU, M.STOKADI, M.YEMEK_KODU1, DBO.FNC_RES_ANAYEMEKADI(M.YEMEK_KODU1)
            ) AS SONTABLO
            GROUP BY KOD, ACIKLAMA, YEMEK_KODU1, YEMEK_ADI1
            ORDER BY NET_TUTAR DESC;
        `);

    
        res.json(result.recordset);
    } catch (err) {
        console.error('SQL sorgu hatası:', err);
        res.status(500).send('Veriler çekilemedi.');
    }
});


app.post('/ana_yemek_detayi', async (req, res) => {
    const { user, password, hostAddress, port, dbName, trhb, trhs } = req.body;
    if (!user || !password || !hostAddress || !port || !dbName || !trhb || !trhs) {
        return res.status(400).send('Parametreler eksik.');
    }

    // Tarih formatlarını kontrol et
    if (!isValidDate(trhb) || !isValidDate(trhs)) {
        return res.status(400).send('Geçersiz tarih formatı.');
    }
    const encodedUserPassword = decodeBase64(password); 
    console.log(encodedUserPassword);
    const startDate = formatDate(trhb);
    const endDate = formatDate(trhs);

    const config = {
        user: user,
        password: encodedUserPassword,
        server: hostAddress,
        port: parseInt(port),
        database: dbName,
        options: {
            encrypt: false,
            trustServerCertificate: true
        }
    };

    try {
        const pool = await getConnectionPool(config);
        
        // Sorguyu çalıştır
        const result = await pool.request().query(`
            SET DATEFORMAT DMY;
            SELECT 
                CONVERT(CHAR(25), ACIKLAMA) AS ACIKLAMA, 
                STR(ROUND(CONVERT(FLOAT, SUM(NET_TUTAR)), 2), 12, 2) AS NET_TUTAR 
            FROM (
                SELECT  
                    M.YEMEK_KODU1 AS KOD, 
                    DBO.FNC_RES_ANAYEMEKADI(M.YEMEK_KODU1) AS ACIKLAMA,
                    SUM(ISNULL((H.SFIY * H.MIKTAR), 0) - ISNULL(ISKONTOTUTARI, 0)) AS NET_TUTAR 
                FROM RESHRY AS H 
                INNER JOIN STKMAS AS M ON (H.STOKKODU = M.STOKKODU) 
                WHERE 
                    H.TARIH BETWEEN CAST(CONVERT(DATETIME, '${startDate}', 120) AS DATETIME) 
                    AND CAST(CONVERT(DATETIME, '${endDate}', 120) AS DATETIME)
                GROUP BY 
                    M.YEMEK_KODU1, 
                    DBO.FNC_RES_ANAYEMEKADI(M.YEMEK_KODU1)
            ) AS SONTABLO 
            GROUP BY ACIKLAMA
            ORDER BY NET_TUTAR DESC;
        `);

  
        res.json(result.recordset);
    } catch (err) {
        console.error('SQL sorgu hatası:', err);
        res.status(500).send('Veriler çekilemedi.');
    }
});

app.post('/odeme_tipi_detay', async (req, res) => {
    const { user, password, hostAddress, port, dbName, trhb, trhs } = req.body;
    if (!user || !password || !hostAddress || !port || !dbName || !trhb || !trhs) {
        return res.status(400).send('Parametreler eksik.');
    }

    // Tarih formatlarını kontrol et
    if (!isValidDate(trhb) || !isValidDate(trhs)) {
        return res.status(400).send('Geçersiz tarih formatı.');
    }

    const startDate = formatDate(trhb);
    const endDate = formatDate(trhs);
    const encodedUserPassword = decodeBase64(password); 
    console.log(encodedUserPassword);
    const config = {
        user: user,
        password: encodedUserPassword,
        server: hostAddress,
        port: parseInt(port),
        database: dbName,
        options: {
            encrypt: false,
            trustServerCertificate: true
        }
    };

    try {
        const pool = await getConnectionPool(config);
        
        // Sorguyu çalıştır
        const result = await pool.request().query(`
            SET DATEFORMAT DMY;
            SELECT 
                DETAY, 
                Str(ROUND(CONVERT(FLOAT, (TUTAR)), 2), 12, 2) AS TUTAR 
            FROM 
                (SELECT 
                    SUM(TUTAR) AS TUTAR, 
                    KART_TIPI AS DETAY,
                    (CASE 
                        WHEN KART_TIPI = 'N' THEN '0'
                        WHEN KART_TIPI = 'B' THEN '1' 
                        WHEN KART_TIPI = 'T' THEN '2' 
                        ELSE '3'
                    END) AS DR 
                 FROM 
                    (SELECT 
                        TUTAR, 
                        (SELECT TOP 1 ACIKLAMA 
                         FROM KRDKRT 
                         WHERE KOD = KARTKODU) AS KART_TIPI 
                     FROM 
                        (SELECT 
                            ISNULL(SUM(ALACAK), 0) AS TUTAR, 
                            KARTKODU 
                         FROM RESHRY 
                         WHERE KOD = 'A' 
                           AND (TARIH BETWEEN CAST(CONVERT(DATETIME, '${startDate} 00:00:00', 120) AS DATETIME)
                                       AND CAST(CONVERT(DATETIME, '${endDate} 23:59:59', 120) AS DATETIME))  
                         GROUP BY KARTKODU
                        ) AS X
                    ) AS Y
                 GROUP BY KART_TIPI 
                ) AS Z 
            WHERE TUTAR > 0 
            ORDER BY DR;
        `);


        res.json(result.recordset);
    } catch (err) {
        console.error('SQL sorgu hatası:', err);
        res.status(500).send('Veriler çekilemedi.');
    }
});
app.post('/garson_analizi', async (req, res) => {
    const { user, password, hostAddress, port, dbName, trhb, trhs } = req.body;
    if (!user || !password || !hostAddress || !port || !dbName || !trhb || !trhs) {
        return res.status(400).send('Parametreler eksik.');
    }

    // Tarih formatlarını kontrol et
    if (!isValidDate(trhb) || !isValidDate(trhs)) {
        return res.status(400).send('Geçersiz tarih formatı.');
    }

    const startDate = formatDate(trhb);
    const endDate = formatDate(trhs);
    const encodedUserPassword = decodeBase64(password); 
    console.log(encodedUserPassword);
    const config = {
        user: user,
        password: encodedUserPassword,
        server: hostAddress,
        port: parseInt(port),
        database: dbName,
        options: {
            encrypt: false,
            trustServerCertificate: true
        }
    };

    try {
        const pool = await getConnectionPool(config);
        
        // Sorguyu çalıştır
        const result = await pool.request().query(`
            SET DATEFORMAT DMY;
            SELECT 
                KULLANICI_ADI, 
                Str(SUM(TOPLAM), 12, 2) AS TOPLAM 
            FROM 
                (SELECT 
                    K_KODU, 
                    KRDRMZ.KULLANICI_ADI, 
                    ISNULL(SFIY, 0) * ISNULL(MIKTAR, 0) - ISNULL(ISKONTOTUTARI, 0) AS TOPLAM 
                 FROM RESHRY 
                 LEFT OUTER JOIN KRDRMZ 
                 ON RESHRY.SATICIKODU = KRDRMZ.K_KODU 
                 WHERE KOD = 'B' 
                   AND (RESHRY.TARIH BETWEEN CAST(CONVERT(DATETIME, '${startDate} 00:00:00', 120) AS DATETIME) 
                                          AND CAST(CONVERT(DATETIME, '${endDate} 23:59:59', 120) AS DATETIME))
                ) AS son 
            GROUP BY KULLANICI_ADI, K_KODU 
            ORDER BY TOPLAM DESC;
        `);

        res.json(result.recordset);
    } catch (err) {
        console.error('SQL sorgu hatası:', err);
        res.status(500).send('Veriler çekilemedi.');
    }
});
app.post('/acikmasa_detay', async (req, res) => {
    const { user, password, hostAddress, port, dbName, trhb, trhs } = req.body;
    if (!user || !password || !hostAddress || !port || !dbName || !trhb || !trhs) {
        return res.status(400).send('Parametreler eksik.');
    }

    // Tarih formatlarını kontrol et
    if (!isValidDate(trhb) || !isValidDate(trhs)) {
        return res.status(400).send('Geçersiz tarih formatı.');
    }

    const startDate = formatDate(trhb);
    const endDate = formatDate(trhs);
    const encodedUserPassword = decodeBase64(password); 
    console.log(encodedUserPassword);
    const config = {
        user: user,
        password: encodedUserPassword,
        server: hostAddress,
        port: parseInt(port),
        database: dbName,
        options: {
            encrypt: false,
            trustServerCertificate: true
        }
    };

    try {
        const pool = await getConnectionPool(config);
        
        // Sorguyu çalıştır
        const result = await pool.request().query(`
            SET DATEFORMAT DMY;
            SELECT 
                MASANOSTR, 
                STOKADI,
                Str(SUM(CAST(MIKTAR AS float)), 12, 2) AS MIKTAR,
                Str(CAST(SFIY AS float), 12, 2) AS SFIY,
                (SUM(SFIY * MIKTAR)) AS TUTAR 
            FROM RESCEK 
            WHERE 1 = 1
            GROUP BY MASANOSTR, STOKADI, SFIY
            ORDER BY MASANOSTR;
        `);


        res.json(result.recordset);
    } catch (err) {
        console.error('SQL sorgu hatası:', err);
        res.status(500).send('Veriler çekilemedi.');
    }
});
app.post('/departman_satisi', async (req, res) => {
    // React Native tarafından gönderilen parametreleri al
    const { user, password, hostAddress, port, dbName, trhb, trhs } = req.body;
    if (!user || !password || !hostAddress || !port || !dbName || !trhb || !trhs) {
        return res.status(400).send('Parametreler eksik.');
    }

    // Tarih formatlarını kontrol et
    if (!isValidDate(trhb) || !isValidDate(trhs)) {
        return res.status(400).send('Geçersiz tarih formatı.');
    }
    const encodedUserPassword = decodeBase64(password); 
    console.log(encodedUserPassword);
    const startDate = formatDate(trhb);
    const endDate = formatDate(trhs);

    const config = {
        user: user,
        password: encodedUserPassword,
        server: hostAddress,
        port: parseInt(port),
        database: dbName,
        options: {
            encrypt: false,
            trustServerCertificate: true
        }
    };

    try {
        const pool = await getConnectionPool(config);
        
        // Sorguyu çalıştır
        const result = await pool.request().query(`
            SET DATEFORMAT dmy;
            SELECT 
                M.DEPARTMAN_KODU, 
                DBO.FNC_RES_DEPARTMANADI(M.DEPARTMAN_KODU) AS DEPARTMAN_ADI, 
                SUM(ISNULL(H.MIKTAR * H.SFIY,0)) AS NET_TUTAR,  
                SUM(H.ISKONTOTUTARI) AS ISKONTO,
                SUM(ISNULL(H.MIKTAR * H.SFIY,0) - ISNULL(H.ISKONTOTUTARI,0)) AS TUTAR,
                SUM(H.MIKTAR) AS MIKTAR
            FROM RESHRY AS H 
            INNER JOIN RESMASA AS M ON (H.MASANO = M.MASANO)  
            WHERE H.TARIH BETWEEN CAST(CONVERT(DATETIME, '${startDate} 00:00:00', 120) AS DATETIME) 
                            AND CAST(CONVERT(DATETIME, '${endDate} 23:59:59', 120) AS DATETIME)
                AND H.KOD = 'B' 
            GROUP BY H.KARTKODU, M.DEPARTMAN_KODU;
        `);

       
        res.json(result.recordset);
    } catch (err) {
        console.error('SQL sorgu hatası:', err);
        res.status(500).send('Veriler çekilemedi.');
    }
});
app.post('/acikmasalar', async (req, res) => {
    const { user, password, hostAddress, port, dbName, trhb, trhs } = req.body;
    if (!user || !password || !hostAddress || !port || !dbName || !trhb || !trhs) {
        return res.status(400).send('Parametreler eksik.');
    }

    // Tarih formatlarını kontrol et
    if (!isValidDate(trhb) || !isValidDate(trhs)) {
        return res.status(400).send('Geçersiz tarih formatı.');
    }
    const encodedUserPassword = decodeBase64(password); 
    console.log(encodedUserPassword);
    const startDate = formatDate(trhb);
    const endDate = formatDate(trhs);

    const config = {
        user: user,
        password: encodedUserPassword,
        server: hostAddress,
        port: parseInt(port),
        database: dbName,
        options: {
            encrypt: false,
            trustServerCertificate: true
        }
    };

    try {
        const pool = await getConnectionPool(config);
        
        // Sorguyu çalıştır
        const result = await pool.request().query(`
            SET DATEFORMAT DMY;
            SELECT 
                MASANOSTR,
                (SELECT TOP 1 KISI_SAYISI 
                 FROM RESYAZ 
                 WHERE RESYAZ.CEKNO = rescek.CEKNO) AS KISI,
                DBO.FNC_RES_CekTutari(RESCEK.CEKNO) AS TUTAR,
                CEKNO,
                ADISYON_TIPI
            FROM RESCEK
            GROUP BY MASANOSTR, CEKNO, ADISYON_TIPI
            ORDER BY MASANOSTR;
        `);

        res.json(result.recordset);
    } catch (err) {
        console.error('SQL sorgu hatası:', err);
        res.status(500).send('Veriler çekilemedi.');
    }
});
app.post('/ikram_ve_indirimler', async (req, res) => {
    const { user, password, hostAddress, port, dbName, trhb, trhs } = req.body;
    if (!user || !password || !hostAddress || !port || !dbName || !trhb || !trhs) {
        return res.status(400).send('Parametreler eksik.');
    }

    // Tarih formatlarını kontrol et
    if (!isValidDate(trhb) || !isValidDate(trhs)) {
        return res.status(400).send('Geçersiz tarih formatı.');
    }
    const encodedUserPassword = decodeBase64(password); 
    console.log(encodedUserPassword);
    const startDate = formatDate(trhb);
    const endDate = formatDate(trhs);

    const config = {
        user: user,
        password: encodedUserPassword,
        server: hostAddress,
        port: parseInt(port),
        database: dbName,
        options: {
            encrypt: false,
            trustServerCertificate: true
        }
    };

    try {
        const pool = await getConnectionPool(config);
        
        // Sorguyu çalıştır
        const result = await pool.request().query(`
            SET DATEFORMAT dmy;
            SELECT 
                KRDKRT.ACIKLAMA, 
                BORCLAR AS TUTAR
            FROM 
            (
                SELECT 
                    KARTKODU, 
                    ISNULL(SUM(ISKONTOTUTARI1), 0) AS BORCLAR, 
                    ISNULL(SUM(ALACAK), 0) AS TUTAR 
                FROM RESHRY 
                WHERE KOD = 'A'
                AND (TARIH BETWEEN CAST(CONVERT(DATETIME, '${startDate} 00:00:00', 120) AS DATETIME) 
                                AND CAST(CONVERT(DATETIME, '${endDate} 23:59:59', 120) AS DATETIME))
                GROUP BY KARTKODU
            ) ODEMELER
            LEFT OUTER JOIN KRDKRT ON KRDKRT.KOD = ODEMELER.KARTKODU
            WHERE ODEMELER.TUTAR = 0
            ORDER BY TUTAR DESC;
        `);


        res.json(result.recordset);
    } catch (err) {
        console.error('SQL sorgu hatası:', err);
        res.status(500).send('Veriler çekilemedi.');
    }
});
app.post('/iptaller', async (req, res) => {
    const { user, password, hostAddress, port, dbName, trhb, trhs } = req.body;
    if (!user || !password || !hostAddress || !port || !dbName || !trhb || !trhs) {
        return res.status(400).send('Parametreler eksik.');
    }

    // Tarih formatlarını kontrol et
    if (!isValidDate(trhb) || !isValidDate(trhs)) {
        return res.status(400).send('Geçersiz tarih formatı.');
    }
    const encodedUserPassword = decodeBase64(password); 
    console.log(encodedUserPassword);
    const startDate = formatDate(trhb);
    const endDate = formatDate(trhs);

    const config = {
        user: user,
        password: encodedUserPassword,
        server: hostAddress,
        port: parseInt(port),
        database: dbName,
        options: {
            encrypt: false,
            trustServerCertificate: true
        }
    };

    try {
        const pool = await getConnectionPool(config);
        
        // Sorguyu çalıştır
        const result = await pool.request().query(`
            SET DATEFORMAT dmy;
            SELECT  
                Str(ROUND(CONVERT(FLOAT, SUM(ISNULL(NET_TUTAR, 0))), 2), 12, 2) AS NET_TUTAR, 
                CONVERT(NVARCHAR, cekno) + ' ' + ACIKLAMA AS ACIKLAMA 
            FROM ( 
                SELECT 
                    cekno, 
                    NET_TUTAR,
                    ACIKLAMA 
                FROM (
                    SELECT 
                        (SELECT TOP 1 RESHRY.CEKNO FROM RESHRY WHERE CEKNO = H.CEKNO) AS RESHRY_CEKNO, 
                        H.ACIKLAMA,  
                        H.STOKKODU, 
                        H.CEKNO,
                        H.MASANO, 
                        dbo.FNC_STK_STOKADI(H.STOKKODU) AS STOKADI, 
                        IPT_KULLANICI_KODU, 
                        IPT_TARIHI, 
                        SUBSTRING(EKLENEN_SAAT, 1, 5) AS EKLENEN_SAAT, 
                        CONVERT(VARCHAR(5), IPT_TARIHI, 108) AS IPT_SAATI, 
                        DBO.FNC_KRD_KULLANICIADI(H.IPT_KULLANICI_KODU) AS IPT_YAPAN, 
                        DBO.FNC_KRD_KULLANICIADI(H.SATICIKODU) AS SATICI,   
                        SUM(H.MIKTAR) AS MIKTAR, 
                        SUM(H.MIKTAR * H.SFIY) AS SFIY, 
                        SUM(H.ISKONTOTUTARI) AS ISKONTO,  
                        SUM(ISNULL((H.SFIY * H.MIKTAR), 0) - ISNULL(ISKONTOTUTARI, 0)) AS NET_TUTAR,
                        MASANOSTR 
                    FROM RESIPT AS H  
                    LEFT OUTER JOIN KRDRMZ ON H.SATICIKODU = KRDRMZ.K_KODU   
                    WHERE (H.TARIH BETWEEN CAST(CONVERT(DATETIME, '${startDate} 00:00:00', 120) AS DATETIME)
                                   AND CAST(CONVERT(DATETIME, '${endDate} 23:59:59', 120) AS DATETIME))
                    AND H.KOD = 'B' 
                    GROUP BY H.STOKKODU, H.CEKNO, H.MASANO, H.SATICIKODU, IPT_KULLANICI_KODU, IPT_TARIHI, 
                             H.ACIKLAMA, H.MASANOSTR, EKLENEN_SAAT 
                ) ds 
            ) DF 
            GROUP BY cekno, ACIKLAMA 
            ORDER BY CEKNO;
        `);


        res.json(result.recordset);
    } catch (err) {
        console.error('SQL sorgu hatası:', err);
        res.status(500).send('Veriler çekilemedi.');
    }
});
app.post('/masrafdetay', async (req, res) => {
    // React Native tarafından gönderilen parametreleri al
    const { user, password, hostAddress, port, dbName, trhb, trhs } = req.body;
    if (!user || !password || !hostAddress || !port || !dbName || !trhb || !trhs) {
        return res.status(400).send('Parametreler eksik.');
    }
    const encodedUserPassword = decodeBase64(password); 
    console.log(encodedUserPassword);

    const dbConfig = {
        user: user,
        password: encodedUserPassword,
        server: hostAddress,
        port: parseInt(port),
        database: dbName,
        options: {
            encrypt: false,
            trustServerCertificate: true
        }
    };

    try {
        // Veritabanına bağlantıyı aç
        await sql.connect(dbConfig);
        
        // SQL sorgusunu yaz
        const query = `
            SET DATEFORMAT dmy;
            SELECT 
                HESAPADI, 
                ACIKLAMA, 
                Str(CAST(ALACAK AS FLOAT), 12, 2) AS ALACAK 
            FROM KASHRY 
            WHERE ALACAK > 0 
            AND TARIH BETWEEN CAST(CONVERT(DATE, '${trhb} 00:00:00', 104) AS DATE) 
                          AND CAST(CONVERT(DATE, '${trhs} 23:59:59', 104) AS DATETIME);
        `;

        // Sorguyu çalıştır ve sonucu al
        const result = await sql.query(query);
        
        // Sonucu JSON olarak döndür
        res.json(result.recordset);
    } catch (err) {
        // Hata durumunda, detaylı hata mesajını logla
        console.error('SQL sorgu hatası:', err);
        console.error('Hata kodu:', err.code);  // Hata kodunu da yazdırarak daha fazla bilgi alabilirsiniz
        console.error('Hata mesajı:', err.message);  // Hata mesajını daha açık yazdırmak için
        if (err.response) {
            console.error('Yanıt Detayı:', err.response.data);  // Axios yanıtı varsa detayları yazdır
        }
        
        // Hata mesajını istemciye döndür
        res.status(500).send('Veriler çekilemedi.');
    }
});





app.listen(PORT, () => { 
    console.log(`RESTful API sunucusu ${PORT} numaralı portta çalışıyor.`); 
});
