-- Product:  Qualys(R)
-- Subject:  MS SQL Server Compliance Scan - Privilege checker script
-- Filename: QG_MSSQLServer_Auth_ver1.1.sql
-- Date:     Sep 10 2024
-- Description: This script can help you identify which privileges may be missing from the user account to be used for MS SQL Server authenticated scanning. This script should be executed by a super-user against a database to determine if all the appropriate privileges have been setup correctly. The script will generate an output listing the status of all the prerequisites.
-- For More Information: See the Qualys Tips & Techniques document called "MS SQL Server Authentication (PC)". This document is available for download from the Resources section of your account (Help > Resources > Scan Authentication).

-- Instructions: 
-- 1. Update <scan_login> with the scan login name created, for example some_server\some_windows_acct or some_sql_login
-- 2. Update <scan_user> with the scan user name created, for example some_sql_user
-- 3. Update <some database> with the user database to be assessed
-- 4. Execute this script using an account with administrative privilege or the scan login. 

-- Currently logged in as who, where, what
SELECT @@servername + '_' + @@servicename Server_servicename, db_name() DB_name, USER_NAME() Username, SUSER_NAME() Suser_name

DECLARE @scanlogin AS varchar(100), @scanuser AS varchar(100), @scanloginsid AS varchar(20), @scanuserdid AS varchar(20)

/*Modify these values to match your environment*/
SELECT @scanlogin = 'DOMAIN\SVC_T1Qualys_SQL'
SELECT @scanuser = 'SVC_T1Qualys_SQL'

USE [master]
SELECT @scanloginsid = suser_id(@scanlogin)
SELECT @scanuserdid = user_id(@scanuser)
PRINT 'scan login: '+ @scanlogin + ' scan login sid: ' + @scanloginsid 
PRINT '--'
PRINT 'scan user: '+ @scanuser + ' scan user did: ' + @scanuserdid

SELECT db_name() Prerequisites, 'Current Database' Status
UNION
SELECT SUSER_NAME() Prerequisites, 'Current logged in user' Status
UNION
SELECT CONVERT(char(20),serverproperty('productversion')) Prerequisites, 'Current product version' Status
UNION 
SELECT @scanlogin Prerequisites, 
CASE inv00.check00 WHEN 0 THEN 'FAILED - Server principal does not exist'
WHEN 1 THEN 'PASS - Server principal exists' END AS Status FROM
(SELECT COUNT(type) check00 FROM sys.server_principals WHERE name = @scanlogin) inv00
UNION 
SELECT @scanuser Prerequisites, 
CASE inv0.check0 WHEN 0 THEN 'FAILED - Database principal does not exist'
WHEN 1 THEN 'PASS - Database principal exists' END AS Status FROM
(SELECT COUNT(type) check0 FROM sys.database_principals WHERE name = @scanuser) inv0
UNION
SELECT 'VIEW ANY DEFINITION' Prerequisites, 
CASE inv1.check1 WHEN 0 THEN 'FAILED - Privilege does not exist'
WHEN 1 THEN 'PASS - Privilege exists' END AS Status FROM
(SELECT COUNT(type) check1 FROM sys.server_permissions WHERE permission_name = 'VIEW ANY DEFINITION' 
AND grantee_principal_id = @scanloginsid AND state_desc LIKE 'GRANT%') inv1
UNION 
SELECT 'VIEW SERVER STATE' Prerequisites, 
CASE inv2.check2 WHEN 0 THEN 'FAILED - Privilege does not exist'
WHEN 1 THEN 'PASS - Privilege exists' END AS Status FROM
(SELECT COUNT(type) check2 FROM sys.server_permissions WHERE permission_name = 'VIEW SERVER STATE' 
AND grantee_principal_id = @scanloginsid AND state_desc LIKE 'GRANT%') inv2
UNION 
SELECT 'ALTER TRACE' Prerequisites, 
CASE inv3.check3 WHEN 0 THEN 'FAILED - Privilege does not exist'
WHEN 1 THEN 'PASS - Privilege exists' END AS Status FROM
(SELECT COUNT(type) check3 FROM sys.server_permissions WHERE permission_name = 'ALTER TRACE' 
AND grantee_principal_id = @scanloginsid AND state_desc LIKE 'GRANT%') inv3
UNION 
SELECT 'XP_LOGINCONFIG' Prerequisites, 
CASE inv4.check4 WHEN 0 THEN 'FAILED - Execute privilege does not exist'
WHEN 1 THEN 'PASS - Execute privilege exists' END AS Status FROM
(SELECT COUNT(name) check4 FROM sys.database_permissions a, sys.all_objects b 
WHERE b.name = 'xp_loginconfig' AND a.major_id = b.object_id AND a.state_desc LIKE 'GRANT%'
AND USER_NAME(a.grantee_principal_id) = @scanuser) inv4
ORDER BY 2,1

-- if you are intending to assess msdb database
USE [msdb]
SELECT db_name() Prerequisites, 'Current Database' Status
UNION
SELECT SUSER_NAME() Prerequisites, 'Current logged in user' Status
UNION
SELECT @scanuser Prerequisites, 
CASE inv0.check0 WHEN 0 THEN 'FAILED - Database principal does not exist'
WHEN 1 THEN 'PASS - Database principal exists' END AS Status FROM
(SELECT COUNT(type) check0 FROM sys.database_principals WHERE name = @scanuser) inv0
UNION
SELECT 'SP_ENUM_LOGIN_FOR_PROXY' Prerequisites, 
CASE inv1.check1 WHEN 0 THEN 'FAILED - Execute privilege does not exist'
WHEN 1 THEN 'PASS - Execute privilege exists' END AS Status FROM
(SELECT COUNT(name) check1 FROM sys.database_permissions a, sys.all_objects b 
WHERE b.name = 'SP_ENUM_LOGIN_FOR_PROXY' AND a.major_id = b.object_id AND a.state_desc LIKE 'GRANT%'
AND USER_NAME(a.grantee_principal_id) = @scanuser) inv1
UNION
SELECT 'SP_ENUM_PROXY_FOR_SUBSYSTEM' Prerequisites, 
CASE inv2.check2 WHEN 0 THEN 'FAILED - Execute privilege does not exist'
WHEN 1 THEN 'PASS - Execute privilege exists' END AS Status FROM
(SELECT COUNT(name) check2 FROM sys.database_permissions a, sys.all_objects b 
WHERE b.name = 'SP_ENUM_PROXY_FOR_SUBSYSTEM' AND a.major_id = b.object_id AND a.state_desc LIKE 'GRANT%'
AND USER_NAME(a.grantee_principal_id) = @scanuser) inv2
UNION
SELECT 'SYSPROXIES' Prerequisites, 
CASE inv3.check3 WHEN 0 THEN 'FAILED - Select privilege does not exist'
WHEN 1 THEN 'PASS - Select privilege exists' END AS Status FROM
(SELECT COUNT(name) check3 FROM sys.database_permissions a, sys.all_objects b 
WHERE b.name = 'SYSPROXIES' AND a.major_id = b.object_id AND a.state_desc LIKE 'GRANT%'
AND USER_NAME(a.grantee_principal_id) = @scanuser) inv3
UNION
SELECT 'SYSPROXYLOGIN' Prerequisites, 
CASE inv4.check4 WHEN 0 THEN 'FAILED - Select privilege does not exist'
WHEN 1 THEN 'PASS - Select privilege exists' END AS Status FROM
(SELECT COUNT(name) check4 FROM sys.database_permissions a, sys.all_objects b 
WHERE b.name = 'SYSPROXYLOGIN' AND a.major_id = b.object_id AND a.state_desc LIKE 'GRANT%'
AND USER_NAME(a.grantee_principal_id) = @scanuser) inv4
ORDER BY 2,1;


-- if you are intending to assess user database
DECLARE @sql VARCHAR(MAX)
SET @sql = 'DECLARE @scanuser AS varchar(100)
SELECT @scanuser = ''' + @scanuser + '''
SELECT db_name() Prerequisites, ''Current Database'' Status
UNION
SELECT SUSER_NAME() Prerequisites, ''Current logged in user'' Status
UNION
SELECT @scanuser Prerequisites, 
CASE inv0.check0 WHEN 0 THEN ''FAILED - Database principal does not exist''
WHEN 1 THEN ''PASS - Database principal exists'' END AS Status FROM
(SELECT COUNT(type) check0 FROM sys.database_principals WHERE name = @scanuser) inv0
ORDER BY 2,1'

DECLARE @dbname SYSNAME
DECLARE db_cursor CURSOR FOR
    SELECT name FROM sys.databases
    WHERE state = 0 AND database_id > 4

OPEN db_cursor
FETCH NEXT FROM db_cursor INTO @dbname
WHILE @@FETCH_STATUS = 0
BEGIN
    EXEC ('USE [' + @dbname + ']; ' + @sql)
    FETCH NEXT FROM db_cursor INTO @dbname
END
CLOSE db_cursor
DEALLOCATE db_cursor