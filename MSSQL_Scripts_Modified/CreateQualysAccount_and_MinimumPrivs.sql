/************************************************************************************************************ 
FILENAME    : CreateQualysAccount_and_MinimumPrivs.sql

DESCRIPTION : This SQL script creates a Qualys account and sets minimal rights on MS SQL DBs.
			  First part creates the needed accounts on all DBs and sets the minimum required 
			  privileges for Qualys assessment. Second part defines a SQL Agent job to 
			  create Qualys user in all databases (if new databases would have been added).
			  
			  Please, note that this script contains generic accounts as example. It is 
			  required to adapt it to the entity's service accounts created for the scans.
			  It is requested to DBAs to review it before executing.

************************************************************************************************************
************************************************************************************************************/

------------------------------------------------------------------------------------------

/*Replace "DOMAIN" and account "SVC_T1Qualys_SQL" as needed below*/


DECLARE @DOMAIN VARCHAR(20) = 'DOMAIN'
DECLARE @SVC_ACCOUNT_USER VARCHAR(30) = 'SVC_T1Qualys_SQL'
DECLARE @SVC_ACCOUNT VARCHAR(128) = @DOMAIN + '\' + @SVC_ACCOUNT_USER

PRINT ''
PRINT 'Begin Add Qualys account & grant minimal rights'
PRINT '-----------------------------------------------'

------------------------------------------------------------------------------------------------
-- Add limited rights to the Qualys accounts
-- Script created by THERY Gonzague, adapted by GUILLUY Nele (added TRY / CATCH & IF NOT EXISTS)
-- 2026/07/23: Modified by PEREZ FERNANDEZ-CORUGEDO Ignacio
------------------------------------------------------------------------------------------------

PRINT '-- Create Qualys login'; 
BEGIN TRY
     DECLARE @SQLQualysLogin VARCHAR(1500)
	 SET @SQLQualysLogin = 'IF NOT EXISTS (SELECT name FROM master.sys.server_principals WHERE name = ''' + @SVC_ACCOUNT + ''')
			 CREATE LOGIN [' + @SVC_ACCOUNT + '] FROM WINDOWS WITH DEFAULT_DATABASE=[master];'
	EXEC(@SQLQualysLogin)
END TRY

BEGIN CATCH
     PRINT  'Error creating login for ' + @SVC_ACCOUNT + ': ' + ERROR_MESSAGE()
END CATCH;

-------------------------------------------------------------------------------------------------------

PRINT '-- Create Qualys user in all databases'; 
USE [master]
DECLARE @SQLCreateUser VARCHAR(1500)
SET @SQLCreateUser = 'IF EXISTS (SELECT name FROM master.sys.server_principals WHERE name = ''' + @SVC_ACCOUNT + ''')
	EXEC sp_MSforeachdb N''USE [?]; PRINT ''''?''''; IF NOT EXISTS(SELECT name FROM sys.database_principals WHERE name = ''''' + @SVC_ACCOUNT + ''''') 
	CREATE USER [' + @SVC_ACCOUNT_USER + '] FOR login [' + @SVC_ACCOUNT + ']''' 
EXEC(@SQLCreateUser)

-------------------------------------------------------------------------------------------------------

PRINT '-- GRANT SERVER LEVEL access'
USE [master]
DECLARE @SQLServerLevelAccess VARCHAR(1500)
SET @SQLServerLevelAccess = 'IF EXISTS (SELECT name FROM master.sys.server_principals WHERE name = ''' + @SVC_ACCOUNT + ''')
	BEGIN
		GRANT ALTER TRACE TO [' + @SVC_ACCOUNT + ']
		GRANT VIEW SERVER STATE TO [' + @SVC_ACCOUNT + ']
		GRANT VIEW ANY DEFINITION TO [' + @SVC_ACCOUNT + ']
		GRANT EXECUTE ON xp_loginconfig TO [' + @SVC_ACCOUNT_USER + ']
	END
	ELSE PRINT ''ERROR: Login for ' + @SVC_ACCOUNT + ' not found. Skipping.'''
EXEC(@SQLServerLevelAccess)

-------------------------------------------------------------------------------------------------------

PRINT '-- GRANT SELECT on objects'
USE [master]
DECLARE @SQLServerSelectObjects VARCHAR(1500)
SET @SQLServerSelectObjects = 'IF EXISTS (SELECT name FROM master.sys.server_principals WHERE name = ''' + @SVC_ACCOUNT + ''')
	BEGIN
		GRANT SELECT ON sys.all_objects TO [' + @SVC_ACCOUNT_USER + ']
		GRANT SELECT ON sys.configurations TO [' + @SVC_ACCOUNT_USER + ']
		GRANT SELECT ON sys.databases TO [' + @SVC_ACCOUNT_USER + ']
		GRANT SELECT ON sys.database_permissions TO [' + @SVC_ACCOUNT_USER + ']
		GRANT SELECT ON sys.syslogins TO [' + @SVC_ACCOUNT_USER + ']
		GRANT SELECT ON sys.trace_events TO [' + @SVC_ACCOUNT + ']
		GRANT SELECT ON sys.traces TO [' + @SVC_ACCOUNT_USER + ']
		GRANT SELECT ON sys.sysaltfiles TO [' + @SVC_ACCOUNT_USER + ']
		GRANT SELECT ON sys.server_principals TO [' + @SVC_ACCOUNT_USER + ']

	END
    ELSE PRINT ''ERROR: Login for ' + @SVC_ACCOUNT + ' not found. Skipping.'''
EXEC(@SQLServerSelectObjects)

-------------------------------------------------------------------------------------------------------

PRINT '-- GRANT SELECT on msdb'
use [msdb]
DECLARE @SQLServerSelectMsdb VARCHAR(1500)
SET @SQLServerSelectMsdb = 'IF EXISTS (SELECT name FROM master.sys.server_principals WHERE name = ''' + @SVC_ACCOUNT + ''')
	BEGIN
		GRANT EXECUTE ON msdb..sp_enum_login_for_proxy TO [' + @SVC_ACCOUNT_USER + ']
		GRANT EXECUTE ON msdb..sp_enum_proxy_for_subsystem TO [' + @SVC_ACCOUNT_USER + ']
		GRANT SELECT ON msdb..sysproxies TO [' + @SVC_ACCOUNT_USER + ']
		GRANT SELECT ON msdb..sysproxylogin TO [' + @SVC_ACCOUNT_USER + ']
	END'
EXEC(@SQLServerSelectMsdb)

-------------------------------------------------------------------------------------------------------
-- Create SQL Agent job to create Qualys user in all databases (if new databases would have been added)
-------------------------------------------------------------------------------------------------------

-- Delete job DBM_GL_Qualys_Miminal_Rights
IF EXISTS (SELECT job_id FROM [msdb].[dbo].[sysjobs] WHERE name = N'DBM_GL_Qualys_Miminal_Rights')
BEGIN
	Print 'Replace DBM_GL_Qualys_Miminal_Rights Job'
	EXEC msdb.dbo.sp_delete_job @job_name=N'DBM_GL_Qualys_Miminal_Rights', @delete_unused_schedule=1
END


-- Create job DBM_GL_Qualys_Miminal_Rights
DECLARE @SQLAgentCode VARCHAR(MAX)
SET @SQLAgentCode = '
BEGIN TRANSACTION
DECLARE @ReturnCode INT
SELECT @ReturnCode = 0

IF NOT EXISTS (SELECT name FROM msdb.dbo.syscategories WHERE name=N''[Uncategorized (Local)]'' AND category_class=1)
BEGIN
EXEC @ReturnCode = msdb.dbo.sp_add_category @class=N''JOB'', @type=N''LOCAL'', @name=N''[Uncategorized (Local)]''
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback

END

DECLARE @jobId BINARY(16)
EXEC @ReturnCode =  msdb.dbo.sp_add_job @job_name=N''DBM_GL_Qualys_Miminal_Rights'', 
		@enabled=1, 
		@notify_level_eventlog=0, 
		@notify_level_email=0, 
		@notify_level_netsend=0, 
		@notify_level_page=0, 
		@delete_level=0, 
		@description=N''Set minimal rights on Qualys technical account'', 
		@category_name=N''[Uncategorized (Local)]'', 
		@owner_login_name=N''sa'', @job_id = @jobId OUTPUT
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [Create_Qualys_Login] ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N''Create_Qualys_Login'', 
		@step_id=1, 
		@cmdexec_success_code=0, 
		@on_success_action=3, 
		@on_success_step_id=0, 
		@on_fail_action=2, 
		@on_fail_step_id=0, 
		@retry_attempts=0, 
		@retry_interval=0, 
		@os_run_priority=0, @subsystem=N''TSQL'', 
		@command=N''BEGIN TRY
     DECLARE @SQLQualysLogin VARCHAR(1500)
	 SET @SQLQualysLogin = ''''IF NOT EXISTS (SELECT name FROM master.sys.server_principals WHERE name = ''''''''' + @SVC_ACCOUNT + ''''''''')
			 CREATE LOGIN [' + @SVC_ACCOUNT + '] FROM WINDOWS WITH DEFAULT_DATABASE=[master];''''
	EXEC(@SQLQualysLogin)
END TRY

BEGIN CATCH
     PRINT  ''''Windows Qualys Account ' + @SVC_ACCOUNT + ' does not exist.'''';
END CATCH;'', 
		@database_name=N''master'', 
		@flags=0
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [Create_Qualys_User] ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N''Create_Qualys_User'', 
		@step_id=2, 
		@cmdexec_success_code=0, 
		@on_success_action=3, 
		@on_success_step_id=0, 
		@on_fail_action=2, 
		@on_fail_step_id=0, 
		@retry_attempts=0, 
		@retry_interval=0, 
		@os_run_priority=0, @subsystem=N''TSQL'', 
		@command=N''USE [master]
DECLARE @SQLQualysLogin VARCHAR(1500)
SET @SQLQualysLogin = ''''IF EXISTS (SELECT name FROM master.sys.server_principals WHERE name = ''''''''' + @SVC_ACCOUNT + ''''''''')
	EXEC sp_MSforeachdb N''''''''USE [?]; IF NOT EXISTS(SELECT name FROM sys.database_principals WHERE name  = ''''''''''''''''' + @SVC_ACCOUNT + ''''''''''''''''') CREATE USER [' + @SVC_ACCOUNT_USER + '] FROM login [' + @SVC_ACCOUNT + ']'''''''''''' 
EXEC(@SQLQualysLogin)'', 
		@database_name=N''master'', 
		@flags=0
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [Grant_Server_Level_Access] ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N''Grant_Server_Level_Access'', 
		@step_id=3, 
		@cmdexec_success_code=0, 
		@on_success_action=3, 
		@on_success_step_id=0, 
		@on_fail_action=2, 
		@on_fail_step_id=0, 
		@retry_attempts=0, 
		@retry_interval=0, 
		@os_run_priority=0, @subsystem=N''TSQL'', 
		@command=N''USE [master]
DECLARE @SQLServerLevelAccess VARCHAR(1500)
SET @SQLServerLevelAccess = ''''IF EXISTS (SELECT name FROM master.sys.server_principals WHERE name = ''''''''' + @SVC_ACCOUNT + ''''''''')
	BEGIN
		GRANT ALTER TRACE TO [' + @SVC_ACCOUNT + ']
		GRANT VIEW SERVER STATE TO [' + @SVC_ACCOUNT + ']
		GRANT VIEW ANY DEFINITION TO [' + @SVC_ACCOUNT + ']
		GRANT EXECUTE ON xp_loginconfig TO [' + @SVC_ACCOUNT_USER + ']
	END''''
EXEC(@SQLServerLevelAccess)'', 
		@database_name=N''master'', 
		@flags=0
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [Grant_Select_On_Objects] ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N''Grant_Select_On_Objects'', 
		@step_id=4, 
		@cmdexec_success_code=0, 
		@on_success_action=3, 
		@on_success_step_id=0, 
		@on_fail_action=2, 
		@on_fail_step_id=0, 
		@retry_attempts=0, 
		@retry_interval=0, 
		@os_run_priority=0, @subsystem=N''TSQL'', 
		@command=N''USE [master]
DECLARE @SQLServerSelectObjects VARCHAR(1500)
SET @SQLServerSelectObjects = ''''IF EXISTS (SELECT name FROM master.sys.server_principals WHERE name = ''''''''' + @SVC_ACCOUNT + ''''''''')
	BEGIN
		GRANT SELECT ON sys.all_objects TO [' + @SVC_ACCOUNT_USER+ ']
		GRANT SELECT ON SYS.CONFIGURATIONS TO [' + @SVC_ACCOUNT_USER+ ']
		GRANT SELECT ON SYS.DATABASES TO [' + @SVC_ACCOUNT_USER+ ']
		GRANT SELECT ON SYS.DATABASE_PERMISSIONS TO [' + @SVC_ACCOUNT_USER+ ']
		GRANT SELECT ON SYS.SYSLOGINS TO [' + @SVC_ACCOUNT_USER+ ']
		GRANT SELECT ON SYS.TRACE_EVENTS TO [' + @SVC_ACCOUNT_USER+ ']
		GRANT SELECT ON SYS.TRACES TO [' + @SVC_ACCOUNT_USER+ ']
		GRANT SELECT ON SYS.SYSALTFILES TO [' + @SVC_ACCOUNT_USER+ ']
		GRANT SELECT ON SYS.SERVER_PRINCIPALS TO [' + @SVC_ACCOUNT_USER+ ']
	END''''
EXEC(@SQLServerSelectObjects)'', 
		@database_name=N''master'', 
		@flags=0
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
/****** Object:  Step [Grant_Select_On_Msdb] ******/
EXEC @ReturnCode = msdb.dbo.sp_add_jobstep @job_id=@jobId, @step_name=N''Grant_Select_On_Msdb'', 
		@step_id=5, 
		@cmdexec_success_code=0, 
		@on_success_action=1, 
		@on_success_step_id=0, 
		@on_fail_action=2, 
		@on_fail_step_id=0, 
		@retry_attempts=0, 
		@retry_interval=0, 
		@os_run_priority=0, @subsystem=N''TSQL'', 
		@command=N''DECLARE @SQLServerSelectMsdb VARCHAR(1500)
SET @SQLServerSelectMsdb = ''''IF EXISTS (SELECT name FROM master.sys.server_principals WHERE name = ''''''''' + @SVC_ACCOUNT+ ''''''''')
	BEGIN
		GRANT EXECUTE ON msdb..sp_enum_login_for_proxy TO [' + @SVC_ACCOUNT_USER + ']
		GRANT EXECUTE ON msdb..sp_enum_proxy_for_subsystem TO [' + @SVC_ACCOUNT_USER + ']
		GRANT SELECT ON msdb..sysproxies TO [' + @SVC_ACCOUNT_USER + ']
		GRANT SELECT ON msdb..sysproxylogin TO [' + @SVC_ACCOUNT_USER + ']

	END''''
EXEC(@SQLServerSelectMsdb)'', 
		@database_name=N''msdb'', 
		@flags=0
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_update_job @job_id = @jobId, @start_step_id = 1
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobschedule @job_id=@jobId, @name=N''Schedule_DBM_GL_Qualys_Minimal_Rights'', 
		@enabled=1, 
		@freq_type=4, 
		@freq_interval=1, 
		@freq_subday_type=1, 
		@freq_subday_interval=0, 
		@freq_relative_interval=0, 
		@freq_recurrence_factor=0, 
		@active_start_date=20220926, 
		@active_end_date=99991231, 
		@active_start_time=10000, 
		@active_end_time=235959
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
EXEC @ReturnCode = msdb.dbo.sp_add_jobserver @job_id = @jobId, @server_name = N''(local)''
IF (@@ERROR <> 0 OR @ReturnCode <> 0) GOTO QuitWithRollback
COMMIT TRANSACTION
GOTO EndSave
QuitWithRollback:
    IF (@@TRANCOUNT > 0) ROLLBACK TRANSACTION
EndSave:
'
EXEC(@SQLAgentCode)
GO

PRINT ''
PRINT 'End Add Qualys account & grant minimal rights'
PRINT '-----------------------------------------------'