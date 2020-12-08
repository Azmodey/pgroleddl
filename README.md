# PGRolesDDL
PostgreSQL Roles DDL script - show role DDL with objects permissions and linked roles

## Sample output
```
Databases:
------------------
Name         oid     
postgres     14187   
appdb        16785   
collectd     16799   
apptest      26064   

Role list:
----------------------------------------------------------
Role                           oid      Login    Superuser
app                            16784    True     False    
backup                         25175    True     False    
monitoring                     16833    True     False    
postgres                       10       True     True     
rep_user                       37271    True     False    
pg_execute_server_program      4571     False    False    
pg_monitor                     3373     False    False    
pg_read_all_settings           3374     False    False    
pg_read_all_stats              3375     False    False    
pg_read_server_files           4569     False    False    
pg_signal_backend              4200     False    False    
pg_stat_scan_tables            3377     False    False    
pg_write_server_files          4570     False    False    
role_jit2                      36679    False    False    

Enter role name for details: app

------------ Database: postgres (datid: 14187) ------------
Find linked role [role_jit2] for scanned role [app]:

------------ Database: appdb (datid: 16785) ------------
- (1) Schema_name [jit], object_name [t_jit], object_type [Table], object_owner [app]
- (1) Grantee [app], privs [INSERT, SELECT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER], privswgo []. Grantor [app}]

Find linked role [role_jit2] for scanned role [app]:
- (1) Schema_name [jit], object_name [t_jit2], object_type [Table], object_owner [postgres]
- (1) Grantee [role_jit2], privs [INSERT, UPDATE, DELETE], privswgo [SELECT]. Grantor [postgres}]

------------ Database: collectd (datid: 16799) ------------
Find linked role [role_jit2] for scanned role [app]:

------------ Database: apptest (datid: 26064) ------------
- (1) Schema_name [jit], object_name [t_jit], object_type [Table], object_owner [app]
- (1) Grantee [app], privs [INSERT, SELECT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER], privswgo []. Grantor [app}]

- (2) Schema_name [jit], object_name [t_jit2], object_type [Table], object_owner [app]
- (2) Grantee [app], privs [INSERT, SELECT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER], privswgo []. Grantor [app}]

Find linked role [role_jit2] for scanned role [app]:


------------ Role 'app' DDL ------------
-- DROP ROLE app;

CREATE ROLE app WITH
  NOSUPERUSER
  INHERIT
  NOCREATEROLE
  NOCREATEDB
  LOGIN
  NOREPLICATION
  ENCRYPTED PASSWORD 'md5cac6e0576d309fb8466a2791f0b6ccc7';

GRANT role_jit2 TO app;

-- Grants for role

-- Database: appdb
\c appdb
GRANT INSERT, SELECT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE jit.t_jit TO app;
GRANT INSERT, UPDATE, DELETE ON TABLE jit.t_jit2 TO role_jit2;
GRANT SELECT ON TABLE jit.t_jit2 TO role_jit2 WITH GRANT OPTION;

-- Database: apptest
\c apptest
GRANT INSERT, SELECT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE jit.t_jit TO app;
GRANT INSERT, SELECT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE jit.t_jit2 TO app;

------------ Linked Role 'role_jit2' DDL ------------
-- DROP ROLE role_jit2;

CREATE ROLE role_jit2 WITH
  NOSUPERUSER
  INHERIT
  NOCREATEROLE
  NOCREATEDB
  NOLOGIN
  NOREPLICATION
  ;

GRANT role_jit2 TO app;

-- Grants for role

-- Database: appdb
\c appdb
GRANT INSERT, UPDATE, DELETE ON TABLE jit.t_jit2 TO role_jit2;
GRANT SELECT ON TABLE jit.t_jit2 TO role_jit2 WITH GRANT OPTION;

---------------------------------------------------------
```
