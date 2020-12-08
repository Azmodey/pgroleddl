import os
import psycopg2             # pip install psycopg2
import PGRolesDDLsettings

#
ddl_array = []      # string array for DDL records
roles_array = []    # string array for linked roles
hide_output = 0     # 0 - output for details enable, 1 - disable


'''
GRANT UPDATE, DELETE ON TABLE jit.t_jit TO role_jit2;
GRANT SELECT ON TABLE jit.t_jit TO role_jit2 WITH GRANT OPTION;
'''
# генерация DDL для объекта
# schema_name, object_name, object_type, object_owner, grantee, privileges, privileges with grant option, grantor
def make_ddl(schema_name, object_name, object_type, object_owner, grantee, privs, privswgo, grantor):

    grant_str = ""

    if privs:
        grant_str = "GRANT "+privs+" ON "+object_type.upper()+" "+schema_name+"."+object_name+" TO "+grantee+";"
        ddl_array.append(grant_str)
        # print("DDL: [" + grant_str + "]")

    if privswgo:
        grant_str = "GRANT "+privswgo+" ON "+object_type.upper()+" "+schema_name+"."+object_name+" TO "+grantee+" WITH GRANT OPTION;"
        ddl_array.append(grant_str)
        # print("DDL: [" + grant_str + "]")

#



# Расшифрока строки прав в ACL
def decode_acl_permissions(acl_permissions):
    decoded_acl = ""            # обычные права
    decoded_acl_granted = ""    # права с возможностью передачи (WITH GRANT OPTION)
    i = 0

    while i<len(acl_permissions):
        ret = ""

        a = acl_permissions[i]
        if i<(len(acl_permissions)-1):
            an = acl_permissions[i+1]
        else:
            an = ""

        if (a=="r"):
            ret = "SELECT"
        elif (a=="a"):
            ret = "INSERT"
        elif (a=="w"):
            ret = "UPDATE"
        elif (a=="d"):
            ret = "DELETE"
        elif (a=="D"):
            ret = "TRUNCATE"
        elif (a=="x"):
            ret = "REFERENCES"
        elif (a=="t"):
            ret = "TRIGGER"
        elif (a=="C"):
            ret = "CREATE"
        elif (a=="c"):
            ret = "CONNECT"
        elif (a=="T"):
            ret = "TEMPORARY"
        elif (a=="X"):
            ret = "EXECUTE"
        elif (a=="U"):
            ret = "USAGE"

        # права с возможностью передачи (WITH GRANT OPTION)
        if an == "*":
            decoded_acl_granted = decoded_acl_granted + ret
            if i<(len(acl_permissions)-1):
                decoded_acl_granted = decoded_acl_granted + ", "
        elif a != "*":
            decoded_acl = decoded_acl + ret
            if i<(len(acl_permissions)-1):
                decoded_acl = decoded_acl + ", "

        i += 1

    decoded_acl = decoded_acl.strip(", ")
    decoded_acl_granted = decoded_acl_granted.strip(", ")

    return decoded_acl, decoded_acl_granted

#


'''
Permissions acl (1): [{postgres=arwdDxt/postgres,=r/postgres}]
 - pg_grant [Privileges(grantee='{postgres', grantor='postgres,', privs=['SELECT', 'UPDATE', 'INSERT', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'], privswgo=[])]
Permissions acl (2): [{app=arwdDxt/app}]
 - pg_grant [Privileges(grantee='{app', grantor='app}', privs=['SELECT', 'UPDATE', 'INSERT', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'], privswgo=[])]
Permissions acl (3): [{role_jit2=arwd/postgres}]
 - pg_grant [Privileges(grantee='{app', grantor='app}', privs=['SELECT', 'UPDATE', 'INSERT', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'], privswgo=[])]
'''
# Парсер прав ACL (https://postgrespro.ru/docs/postgrespro/12/ddl-priv)
def parse_acl_item(acl_sting):

    delim_pos1 = acl_sting.find("/")
    delim_pos2 = acl_sting.rfind("/")
    equal_pos1 = acl_sting.find("=")
    equal_pos2 = acl_sting.rfind("=")

    grantee = acl_sting[1:equal_pos1]
    grantee_priv = acl_sting[equal_pos1+1:delim_pos1]
    grantee_priv_decoded_result = decode_acl_permissions(grantee_priv)
    grantee_priv_decoded_acl = grantee_priv_decoded_result[0]
    grantee_priv_decoded_acl_granted = grantee_priv_decoded_result[1]

    # {postgres=arwdDxt/postgres,=r/postgres}
    grantor = acl_sting[delim_pos1+1:len(acl_sting)]
    grantor_pos1 = grantor.find(",")
    if grantor_pos1>0:
        grantor = grantor[0:grantor_pos1]


    '''
    print("--------------------------------------")
    print("Acl parse: ["+acl_sting+"]")

    print("Grantee: ["+grantee+"]")
    print("Grantee privileges: ["+grantee_priv+"]")
    print("Grantee privileges decoded: ["+grantee_priv_decoded_acl+"]")
    print("Grantee privileges with grant option decoded: ["+grantee_priv_decoded_acl_granted+"]")    

    print("Grantor: ["+grantor+"]")

    print("--------------------------------------")
    '''

    return grantee, grantee_priv_decoded_acl, grantee_priv_decoded_acl_granted, grantor
#



# поиск связанным ролям, оттуда опять будет поиск по объектам
def scan_roles(cursor, cursordb, role_name):

    cursor.execute("SELECT pg_roles.rolname, pg_user.usename FROM pg_user JOIN pg_auth_members ON pg_user.usesysid = pg_auth_members.member JOIN pg_roles ON pg_roles.oid = pg_auth_members.roleid  WHERE pg_user.usename = '"+role_name+"';")

    roles_rows = cursor.fetchall()
    for row in roles_rows:
        if hide_output == 0:
            print("Find linked role ["+row[0]+"] for scanned role ["+row[1]+"]:")
    
        roles_array.append(row[0])   # duplicates!
        show_object_permissions(cursordb, row[0])
#



# поиск по объектам БД - таблицы, индексы/процедуры и функции
def show_object_permissions(cursordb, role_name):

    cursordb.execute('''SELECT 
    n.nspname AS schema_name,
    c.relname AS object_name,
    CASE c.relkind WHEN 'r' THEN 'Table' WHEN 't' THEN 'Table TOAST' WHEN 'v' THEN 'View' WHEN 'm' THEN 'Materialized view' WHEN 'c' THEN 'Composite type' WHEN 'i' THEN 'Index' WHEN 'S' THEN 'Sequence' WHEN 's' THEN 'special' WHEN 'f' THEN 'Foreign table' WHEN 'p' THEN 'Partitioned table' WHEN 'I' THEN 'Partitioned Index' ELSE 'other object' END as object_type,
    pg_get_userbyid(c.relowner) AS object_owner,
	c.relacl as object_permissions
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relacl is not null
UNION ALL
SELECT
    n.nspname AS schema_name,
    p.proname as object_name,
	CASE p.prokind WHEN 'f' THEN 'Function' WHEN 'p' THEN 'Procedure' WHEN 'a' THEN 'Aggregate function' WHEN 'w' THEN 'Window function' ELSE 'other proc' END as object_type,
    pg_get_userbyid(p.proowner) AS object_owner,
	p.proacl as object_permissions
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  WHERE p.proacl is not null;''')

    object_rows = cursordb.fetchall()
    records_cnt = 0
    for row in object_rows:

        # parse with build in function "parse_acl_item"
        parse_acl_result = parse_acl_item(row[4])
        parse_acl_grantee = parse_acl_result[0]
        parse_acl_grantee_priv = parse_acl_result[1]
        parse_acl_grantee_priv_granted = parse_acl_result[2]
        parse_acl_grantor = parse_acl_result[3]

        #if (obj_grantee==role_name or obj_grantor==role_name):
        if (parse_acl_grantee==role_name or parse_acl_grantor==role_name):
            records_cnt += 1
            if hide_output == 0:
                print("- ("+str(records_cnt)+") Schema_name [" + row[0] + "], object_name [" + row[1] + "], object_type [" + row[2] + "], object_owner [" + row[3] + "]")
                print("- ("+str(records_cnt)+") Grantee ["+parse_acl_grantee+"], privs ["+parse_acl_grantee_priv+"], privswgo ["+parse_acl_grantee_priv_granted+"]. Grantor ["+parse_acl_grantor+"]")
                print("")

            # schema_name, object_name, object_type, object_owner, grantee, privileges, privileges with grant option, grantor
            make_ddl(row[0], row[1], row[2], row[3], parse_acl_grantee, parse_acl_grantee_priv, parse_acl_grantee_priv_granted, parse_acl_grantor)

#



# проход по базам данных
def scan_databases(cursor, database_rows, role_name):

    cursor.execute("select datid, datname from pg_stat_database where datid<>0 and datname not in ('template0', 'template1') order by datid;")
    database_rows = cursor.fetchall()
    for row in database_rows:
        if hide_output == 0:
            print("------------ Database: " + str(row[1]) + " (datid: " + str(row[0]) + ") ------------")

    #print("Role: ", role_name)

        try:
            conndb = psycopg2.connect(user = pg_user,
                                      password = pg_password,
                                      host = pg_host,
                                      port = pg_port,
                                      database = row[1])

            cursordb = conndb.cursor()
            #print("Connected")

            ddl_array.append("Database: "+str(row[1]))

            # поиск по объектам БД - таблицы, индексы/процедуры и функции
            show_object_permissions(cursordb, role_name)

            # поиск связанным ролям, оттуда опять будет поиск по объектам
            scan_roles(cursor, cursordb, role_name)

        except (Exception, psycopg2.Error) as error :
            print ("Error while connecting to PostgreSQL database [" + str(row[1]) + "]: ", error)
            print("")            
        finally:
            #closing database connection.
                if(conndb):
                    cursordb.close()
                    conndb.close()
                    #print("PostgreSQL database [" + str(row[1]) + "] connection is closed")
                    if hide_output == 0:
                        print("")
#



# Show role DDL
def show_role_ddl(cursor, role_name):

    cursor.execute("SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolconnlimit, rolpassword, rolvaliduntil, rolbypassrls, rolconfig, oid FROM pg_roles WHERE rolname = '"+role_name+"';")

    print("")
    if hide_output == 0:
        print("------------ Role '" + role_name + "' DDL ------------")
    else:
        print("------------ Linked Role '" + role_name + "' DDL ------------")
    print("")
    print("-- DROP ROLE "+role_name+";")
    print("")
    print("CREATE ROLE "+role_name+" WITH")

    role_rows = cursor.fetchall()
    for row in role_rows:
        #print("Find linked role [",row[0],"] for scanned role [",row[1],"]")
        #print("[",row[1],"]")

        if row[1]:  # rolsuper
            print("  SUPERUSER")
        else:
            print("  NOSUPERUSER")

        if row[2]:  # rolinherit
            print("  INHERIT")
        else:
            print("  NOINHERIT")
        
        if row[3]:  # rolcreaterole
            print("  CREATEROLE")
        else:
            print("  NOCREATEROLE")

        if row[4]:  # rolcreatedb
            print("  CREATEDB")
        else:
            print("  NOCREATEDB")

        if row[5]:  # rolcanlogin
            print("  LOGIN")
        else:
            print("  NOLOGIN")

        if row[6]:  # rolreplication
            print("  REPLICATION")
        else:
            print("  NOREPLICATION")

        if row[7]>0:  # rolconnlimit
            print("ALTER ROLE " + role_name + " CONNECTION LIMIT " + row[7] + ";")

        # 8 - rolpassword

        if row[9]:  # rolvaliduntil
            print("ALTER ROLE " + role_name + " VALID UNTIL '" + row[9] + "';")

        # 10 - rolbypassrls

        # 11 - rolconfig

        # 12 - oid
        role_oid = row[12]


        # password
        #cursor.execute("select rolpassword from pg_authid where oid = "+str(role_oid)+";")
        cursor.execute("select passwd from pg_shadow where usesysid = "+str(role_oid)+";")
        role_pass = cursor.fetchone()
        if role_pass:
            role_pass = str(role_pass)
            role_pass = role_pass[2:len(role_pass)-3]
            print("  ENCRYPTED PASSWORD '"+role_pass+"';")
        else:
            print("  ;")


    print("")


    # GRANT ROLES
    cursor.execute("select r1.rolname, r2.rolname, case when admin_option then ' WITH ADMIN OPTION' else '' end from pg_auth_members m join pg_roles r1 on (r1.oid=m.roleid) join pg_roles r2 on (r2.oid=m.member) where (m.member = "+str(role_oid)+" or m.roleid = "+str(role_oid)+") order by m.roleid = "+str(role_oid)+", cast(r2.rolname as text), cast(r1.rolname as text);")
    role_grant_rows = cursor.fetchall()
    for row in role_grant_rows:
        print("GRANT "+row[0]+" TO "+row[1]+";")

    print("")


    # Show objects DDL
    print("-- Grants for role")

    i = 0
    #print("DDL Array: ",ddl_array)
    while i<len(ddl_array):
        ddl_str = ddl_array[i]

        if i<(len(ddl_array)-1):
            ddl_str1 = ddl_array[i+1]
        else:
            ddl_str1 = ""

        if "Database:" in ddl_str:

            if ( ("Database:" not in ddl_str1) and (ddl_str1!="") ):
                print("")
                print("-- "+ddl_str)
                print("\c "+ddl_str[10:len(ddl_str)])

        else:
            print(ddl_str)

        i += 1
        
    print("")


'''
CREATE ROLE app WITH
  LOGIN
  NOSUPERUSER
  INHERIT
  NOCREATEDB
  NOCREATEROLE
  NOREPLICATION
  ENCRYPTED PASSWORD 'md5cac6e0576d309fb8466a2791f0b6ccc7;

GRANT role_jit2 TO app;
'''
#


# -----------------------------------------------------------------
if __name__ == "__main__":

    # from settings
    pg_user = PGRolesDDLsettings.pg_user
    pg_password = PGRolesDDLsettings.pg_password
    pg_host = PGRolesDDLsettings.pg_host
    pg_port = PGRolesDDLsettings.pg_port
    pg_database = PGRolesDDLsettings.pg_database

    
    try:
        connection = psycopg2.connect(user = pg_user,
                                    password = pg_password,
                                    host = pg_host,
                                    port = pg_port,
                                    database = pg_database)

        cursor = connection.cursor()


        # Show Databases
        cursor.execute("select datid, datname from pg_stat_database where datid<>0 and datname not in ('template0', 'template1') order by datid;")
        print("Databases:")
        print("------------------")
        print ("{:<12} {:<8}".format('Name','oid'))
        database_rows = cursor.fetchall()
        for row in database_rows:
            #print("-" + row[1] + " (datid: ",row[0],")")
            print ("{:<12} {:<8}".format(str(row[1]), str(row[0])))
        print("")

        # Show Roles
        cursor.execute("select oid, rolname, rolcanlogin, rolsuper from pg_roles order by rolcanlogin desc, rolname;")
        print("Role list:")
        print("----------------------------------------------------------")
        print ("{:<30} {:<8} {:<8} {:<9}".format('Role','oid','Login', 'Superuser'))
        role_rows = cursor.fetchall()
        for row in role_rows:
            print ("{:<30} {:<8} {:<8} {:<9}".format(str(row[1]), str(row[0]), str(row[2]), str(row[3])))

        # Get and check Role for details
        print("")
        role_name = input("Enter role name for details: ")

        if len(role_name)<=1:
            raise ValueError("- empty value")
        
        role_find = 0
        for row in role_rows:
            if row[1] == role_name:
                role_find = 1

        if role_find == 0:
            raise ValueError("- not in roles list")

        print("")

        
        # Scan role on all databases
        scan_databases(cursor, database_rows, role_name)

        # Show main role DDL
        show_role_ddl(cursor, role_name)

        # Show linked roles DDL
        roles_array = list(dict.fromkeys(roles_array))    # remove duplicates from array
        hide_output = 1
        for linked_role in roles_array:
            ddl_array = []      # string array for DDL records
            scan_databases(cursor, database_rows, linked_role)
            show_role_ddl(cursor, linked_role)
        #

        print("")
        print("---------------------------------------------------------")

    except (Exception, psycopg2.Error) as error :
        print ("Error while connecting to PostgreSQL", error)
    finally:
        #closing database connection.
            if(connection):
                cursor.close()
                connection.close()
                #print("PostgreSQL main connection is closed")

