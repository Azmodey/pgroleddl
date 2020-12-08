# PGRolesDDL
PostgreSQL Roles DDL script - show role DDL with objects permissions and linked roles

## Sample output

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
