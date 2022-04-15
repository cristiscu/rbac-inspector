"""
Created By:    Cristian Scutaru
Creation Date: Nov 2021
Company:       XtractPro Software
"""

import os, sys, re
import argparse
import configparser
import snowflake.connector
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# puts case-sensitive Snowflake names in double-quotes
def getName(name):
    name = name.replace('"', '')
    return name.lower() if re.match("^[A-Z_0-9]*$", name) != None else f'"{name}"'

# convert command line object name to all uppercase if all given in lowercase
def toUpper(name):
    return name.upper() if name == name.lower() else name

class Options:
    def __init__(self):
        # parse command line args
        parser = argparse.ArgumentParser()
        parser.add_argument('--sepusers', dest='sepUsers', nargs='*')
        parser.add_argument('--seproles', dest='sepRoles', nargs='*')
        parser.add_argument('--checkroles', dest='checkRoles', action='store_true')
        parser.add_argument('--user', dest='user')
        parser.add_argument('--role', dest='role')
        parser.add_argument('--users', dest='showUsers', action='store_true')
        parser.add_argument('--roles', dest='showRoles', action='store_true')
        parser.add_argument('--sysroles', dest='showSystemRoles', action='store_true')
        parser.add_argument('--types', dest='objTypes', nargs='*')
        parser.add_argument('--privs', dest='privTypes', nargs='*')
        parser.add_argument('--compact', dest='isCompact', action='store_true')
        args = parser.parse_args()

        # copy into this object
        self.objTypes = args.objTypes
        if self.objTypes != None:
            self.objTypes = [s.upper() for s in self.objTypes]

        self.privTypes = args.privTypes
        if self.privTypes != None:
            self.privTypes = [s.upper().replace('_', ' ') for s in self.privTypes]
        else:
            self.privTypes = []

        self.showSystemRoles = args.showSystemRoles     # False
        self.showUsers = args.showUsers                 # False
        self.showRoles = args.showRoles                 # False
        self.isCompact = args.isCompact                 # False

        self.checkRoles = args.checkRoles               # False
        if self.checkRoles:
            self.showSystemRoles = False
            self.showUsers =  True
            self.objTypes = []
            self.privTypes = []

        self.sepRoles = args.sepRoles                   # None
        if self.sepRoles != None:
            self.sepRoles = [toUpper(s) for s in self.sepRoles]
            self.showRoles = self.showSystemRoles = True
            self.objTypes = []
            self.privTypes = []

        self.sepUsers = args.sepUsers                   # None
        if self.sepUsers != None:
            self.sepUsers = [toUpper(s) for s in self.sepUsers]
            self.showRoles = self.showUsers = self.showSystemRoles = True
            self.objTypes = []
            self.privTypes = []

        self.role = args.role                           # None
        self.user = args.user                           # None
        if self.user != None:
            self.user = toUpper(self.user)
            self.showRoles = self.showUsers = True
        if self.role != None:
            self.role = toUpper(self.role)
            self.showRoles = True
            self.showUsers = False
        if self.user != None or self.role != None:
            self.showRoles = self.showSystemRoles = True

        if not self.showRoles and not self.showUsers and not self.checkRoles:
            print("Usage: python database-inspector.py [options]\n"
                "--sepusers user1 user2 ...         - verifies that listed users access different objects\n"
                "--seproles role1 role2 ...         - verifies that listed roles access different objects\n"
                "--checkroles                       - verifies that we have a two-layer role hierarchy\n"
                "--user user1                       - show inherited roles and privileges only for a user\n"
                "--role role1                       - show inherited roles and privileges only for a role\n"
                "--users                            - show user objects\n"
                "--roles                            - show role objects\n"
                "--sysroles                         - include the system roles\n"
                "--types warehouse schema ...       - the types of objects to include (all if empty)\n"
                "--privs usage manage_grants ...    - the types of privileges (all if empty)\n"
                "--compact                          - compact display (by default per inherited role)\n")
            sys.exit(2)

    @staticmethod
    def isSystemRole(name):
        return name in ["ACCOUNTADMIN", "SYSADMIN", "SECURITYADMIN", "USERADMIN", "PUBLIC", "ORGADMIN"]

    def showRole(self, name):
        return self.showSystemRoles or not Options.isSystemRole(name)

    def showType(self, type):
        return (self.objTypes != None
            and (len(self.objTypes) == 0 or type.upper() in self.objTypes))

    def showPriv(self, priv):
        return len(self.privTypes) == 0 or priv.upper() in self.privTypes

class User:
    def __init__(self, name):
        self.name = name
        self.roles = []
        self.privileges = {}
        self.allRoles = []      # manually updated by getAllRoles()
        self.allPrivs = {}      # auto-updated by getAllPrivs()

    def __eq__(self, other):
        return other != None and self.name == other.name

    def getAllRoles(self, allRoles = []):
        if self not in allRoles:
            allRoles.append(self)
        for role in self.roles:
            role.getAllRoles(allRoles)
        return allRoles

    def getAllPrivs(self, options):
        self.allPrivs = {}
        self.allRoles = self.getAllRoles([])
        for role in self.allRoles:
            for key in role.privileges:
                if key not in self.allPrivs:
                    self.allPrivs[key] = []
                loc = self.allPrivs[key]
                for priv in role.privileges[key]:
                    if priv not in loc:
                        loc.append(priv)
        return self.allPrivs

    def dumpRolesPrivs(self, options):
        if not options.isCompact:
            self.dumpRolesPrivsRecursive()
        else:
            self.allRoles = self.getAllRoles([])
            print("Roles:")
            for role in self.allRoles:
                print(f"  {role.name}")

            self.getAllPrivs(options)
            print("\nPrivileges:")
            for key in self.allPrivs:
                print(f"  {key}: {', '.join(self.allPrivs[key])}")

    def dumpRolesPrivsRecursive(self, visited = [], suffix = ""):
        print(f"{type(self).__name__} {self.name}{suffix}")
        for key in self.privileges:
            print(f"  {key}: {', '.join(self.privileges[key])}")
        print()

        for role in self.roles:
            if role not in visited:
                visited.append(role)
                role.dumpRolesPrivsRecursive(visited, f" <-- {self.name}")

class Role(User):
    def __init__(self, name):
        super().__init__(name)
        self.users = []

    def dumpUsersRolesPrivs(self, options):
        if len(self.users) > 0:
            print("Users:")
            for user in self.users:
                print(f"  {user.name}")
            print()

        super().dumpRolesPrivs(options)

class Object:
    def __init__(self, name, type):
        self.name = name
        self.type = type.lower()
        self.key = f"[{self.type}] {self.name}"
        self.owner = None
        self.parent = None
        self.roles = []

    def getDotName(self):
        name = getName(self.name).replace('"', '')
        return f'"{name}\\n({self.type})"'

def importMetadata(options, users, roles, objects, cur):

    # get all users (or just options.user)
    results = cur.execute("show users").fetchall()
    for row in results:
        if options.user == None or options.user == str(row[0]):
            user = User(str(row[0]))
            users[user.name] = user

    # get all roles
    results = cur.execute("show roles").fetchall()
    for row in results:
        rname = str(row[1])
        if options.showRole(rname):
            role = Role(rname)
            roles[role.name] = role

    # get all user roles
    for uname in users:
        user = users[uname]
        results = cur.execute(f"show grants to user {getName(user.name)}").fetchall()
        for row in results:
            rname = str(row[1])
            if options.showRole(rname):
                role = roles[rname]
                user.roles.append(role)
                role.users.append(user)

    # get hierarchy of roles + ownership + granted object privileges
    for rname in roles:
        role = roles[rname]
        results = cur.execute(f"show grants to role {getName(role.name)}").fetchall()
        for row in results:
            priv = str(row[1])
            type = str(row[2])
            name = str(row[3])
            if type == "ROLE" and priv == "USAGE":
                if options.showRole(name):
                    role2 = roles[name]
                    role.roles.append(role2)
            
            elif options.showType(type) and options.showPriv(priv):
                key = f"[{type.lower()}] {name}"
                if key not in objects:
                    obj = Object(name, type)
                    objects[obj.key] = obj

                    # set parent (create if not there)
                    parts = obj.name.split(".")
                    if len(parts) == 2 and obj.type == "SCHEMA":
                        pname = parts[0]
                        ptype = "database"
                        pkey = f"[{ptype}] {pname}"
                        if pkey not in objects:
                            parent = Object(pname, ptype)
                            objects[pkey] = parent
                        obj.parent = objects[pkey]

                obj = objects[key]
                if role not in obj.roles:
                    obj.roles.append(role)
                
                if priv == "OWNERSHIP":
                    obj.owner = role
                else:
                    if key not in role.privileges:
                        role.privileges[key] = []
                    role.privileges[key].append(priv)

    # if only one user/role --> keep only roles for that user/role
    allRoles = None
    if options.user != None:
        user = users[options.user]
        allRoles = user.getAllRoles([])
    elif options.role != None:
        role = roles[options.role]
        allRoles = role.getAllRoles([])

    if allRoles != None:
        for rname in list(roles.keys()):
            if roles[rname] not in allRoles:
                role = roles[rname]
                for key in list(objects.keys()):
                    obj = objects[key]
                    if role in obj.roles:
                        obj.roles.remove(role)
                        if len(obj.roles) == 0:
                            objects.pop(key, None)
                roles.pop(rname, None)

def getDot(options, users, roles, objects):

    s = ("# You may copy and paste all this to http://viz-js.com/\n\n"
        + "digraph G {\n\n")

    # users
    if options.showUsers and len(users) > 0:
        s += ("  subgraph cluster_0 {\n"
            + "    node [style=filled color=Lavender];\n"
            + "    style=dashed;\n"
            + "    label=users\n\n")
        for uname in users:
            user = users[uname]
            s += f"    {getName(user.name)};\n"
        s += "  }\n"

    # roles
    if options.showRoles and len(roles) > 0:
        s += ("  subgraph cluster_1 {\n"
            "    node [style=filled shape=Mrecord color=LightGray]\n"
            "    style=dashed;\n"
            "    label=roles\n\n")
        for rname in roles:
            role = roles[rname]
            s += f"    {getName(role.name)};\n"
        s += "  }\n"

    # objects
    if options.objTypes != None and len(objects) > 0:
        s += ("  subgraph cluster_2 {\n"
            "    node [style=filled shape=record color=SkyBlue]\n"
            "    style=dashed;\n"
            "    label=objects\n\n")
        for key in objects:
            obj = objects[key]
            s += f'    {obj.getDotName()};\n'
        s += "  }\n"

    # "neil_armstrong" (user) -> "rocketship_administrator" (role)
    if options.showUsers and options.showRoles and len(users) > 0:
        hasHeader = False
        for uname in users:
            user = users[uname]
            for role in user.roles:
                if not hasHeader:
                    s += "\n  // GRANT ROLE role1 TO USER user1\n"
                    hasHeader = True
                s += f"  {getName(user.name)} -> {getName(role.name)};\n"

	# "rocketship_administrator" (role) -> "rocketship_engineer" (role)
    if options.showRoles:
        hasHeader = False
        for rname in roles:
            role = roles[rname]
            for role2 in role.roles:
                if not hasHeader:
                    s += "\n  // GRANT ROLE role1 TO ROLE role2\n"
                    hasHeader = True
                s += f"  {getName(role.name)} -> {getName(role2.name)};\n"

	# "rocketship" (obj) -> "rocketship.public" (obj)
    if options.objTypes != None and len(objects) > 0:
        hasHeader = False
        for key in objects:
            obj = objects[key]
            if obj.parent != None:
                if not hasHeader:
                    s += "\n  // Parent objects\n"
                    hasHeader = True
                s += f"  {obj.parent.getDotName()} -> {obj.getDotName()};\n"

	# "rocketship_administrator" (role) -> "telemetry_sch" (obj) [label="CREATE STAGE"] (privilege)
    if options.showRoles and options.objTypes != None and len(objects) > 0:
        hasHeader = False
        if 'OWNERSHIP' in options.privTypes:
            for key in objects:
                obj = objects[key]
                if obj.owner != None:
                    if not hasHeader:
                        s += "\n  // GRANT OWNERSHIP ON obj1 TO ROLE role2\n"
                        hasHeader = True
                    s += f"  {getName(role.name)} -> {obj.getDotName()} [label=\"OWNERSHIP\"];\n"
        else:
            for rname in roles:
                role = roles[rname]
                for key in role.privileges:
                    if not hasHeader:
                        s += "\n  // GRANT privilege1 TO ROLE role2\n"
                        hasHeader = True
                    privs = "\\n".join(role.privileges[key])
                    s += f"  {getName(role.name)} -> {objects[key].getDotName()} [label=\"{privs}\"];\n"

    s += "}\n"
    return s

def saveDot(options, users, roles, objects, filename):
    # get DOT digraph
    s = getDot(options, users, roles, objects)
    print(s)

    # save in DOT file
    with open(f"{filename}.dot", "w") as file:
        file.write(s)

    # with d3-graphviz
    # https://bl.ocks.org/magjac/4acffdb3afbc4f71b448a210b5060bca
    # https://github.com/magjac/d3-graphviz#creating-a-graphviz-renderer
    s = ('<!DOCTYPE html>\n'
        + '<meta charset="utf-8">\n'
        + '<body>'
        + '<script src="https://d3js.org/d3.v5.min.js"></script>\n'
        + '<script src="https://unpkg.com/@hpcc-js/wasm@0.3.11/dist/index.min.js"></script>\n'
        + '<script src="https://unpkg.com/d3-graphviz@3.0.5/build/d3-graphviz.js"></script>\n'
        + '<div id="graph" style="text-align: center;"></div>\n'
        + '<script>\n'
        + 'var graphviz = d3.select("#graph").graphviz()\n'
        + '   .on("initEnd", () => { graphviz.renderDot(d3.select("#digraph").text()); });\n'
        + '</script>\n'
        + '<div id="digraph" style="display:none;">\n'
        + s
        + '</div>\n')

    # save in HTML file
    with open(f"{filename}.html", "w") as file:
        file.write(s)

def checkSeparateUsers(options, users):
    """
    Verify passed users do not access at all the same database objects
    """

    for name in options.sepUsers:
        if name not in users:
            print(f"??? User {name} not found!")
            return False

    # no role should have MANAGE GRANTS privilege
    sepUsers = []
    for name in options.sepUsers:
        user = users[name]
        sepUsers.append(user)
        user.allRoles = user.getAllRoles([])
        user.getAllPrivs(options)

        for role in user.allRoles:
            for key in role.privileges:
                if key.startswith("[account]") and "MANAGE GRANTS" in role.privileges[key]:
                    print(f"!!! Role {role.name} for user {user.name} has MANAGE GRANTS privilege!")
                    return False

    # display role(s) with privileges
    for user in sepUsers:
        if options.isCompact:
            print(user.name)
            for key in user.allPrivs:
                print(f"  {key}")
            print()
        else:
            for role in user.allRoles:
                suffix = f" (for {user.name})" if role.name != user.name else ""
                print(f"{role.name}{suffix}")

                for key in role.privileges:
                    if not key.startswith("[account]"):
                        print(f"  {key}")
                print()

    areSeparate = True

    # make sure that every two roles (from the right) have no common ancestor
    for i, user in enumerate(sepUsers):
        for roleI in user.allRoles:
            for j, user2 in enumerate(sepUsers):
                if j > i:
                    if roleI in user2.allRoles:
                        print(f"!!! {user.name} and {user2.name} have {roleI.name} as common ancestor role!")
                        areSeparate = False

    # make sure that every two roles (from the right) have no grant for the same db object
    for i, user1 in enumerate(sepUsers):
        for key in user1.allPrivs:
            if not key.startswith("[account]"):
                for j, user2 in enumerate(sepUsers):
                    if j > i:
                        if key in user2.allPrivs:
                            print(f"!!! {user1.name} and {user2.name} both access {key}!")
                            areSeparate = False

    if areSeparate:
        print("The users access different objects.")
    return True

def checkSeparateRoles(options, roles):
    """
    Verify passed roles do not access at all the same database objects
    """

    for name in options.sepRoles:
        if name not in roles:
            print(f"??? Role {name} not found!")
            return False

    # no role should have MANAGE GRANTS privilege
    sepRoles = []
    for name in options.sepRoles:
        role = roles[name]
        sepRoles.append(role)
        role.allRoles = role.getAllRoles([])
        role.getAllPrivs(options)

        for key in role.privileges:
            if key.startswith("[account]") and "MANAGE GRANTS" in role.privileges[key]:
                print(f"!!! Role {role.name} has MANAGE GRANTS privilege!")
                return False

        for role2 in role.allRoles:
            for key in role2.privileges:
                if key.startswith("[account]") and "MANAGE GRANTS" in role2.privileges[key]:
                    print(f"!!! Role {role2.name} has MANAGE GRANTS privilege!")
                    return False

    # display role(s) with privileges
    for role in sepRoles:
        if options.isCompact:
            print(role.name)
            for key in role.allPrivs:
                if not key.startswith("[account]"):
                    print(f"  {key}")
            print()
        else:
            for role2 in role.allRoles:
                suffix = f" (for {role.name})" if role2.name != role.name else ""
                print(f"{role2.name}{suffix}")

                for key in role2.privileges:
                    if not key.startswith("[account]"):
                        print(f"  {key}")
                print()

    areSeparate = True

    # make sure that every 2 roles (from the right) have no common ancestor
    for i, role1 in enumerate(sepRoles):
        for roleI in role1.allRoles:
            for j, role2 in enumerate(sepRoles):
                if j > i:
                    if roleI in role2.allRoles:
                        print(f"!!! {role1.name} and {role2.name} have {roleI.name} as common ancestor role!")
                        areSeparate = False

    # make sure that every 2 roles (from the right) have no grant for the same db object
    for i, role1 in enumerate(sepRoles):
        for key in role1.allPrivs:
            if not key.startswith("[account]"):
                for j, role2 in enumerate(sepRoles):
                    if j > i:
                        if key in role2.allPrivs:
                            print(f"!!! {role1.name} and {role2.name} both access {key}!")
                            areSeparate = False
    
    if areSeparate:
        print("The roles access different objects.")
    return True

def checkRoles(options, users):
    """
    Send warning for roles assigned to users AND with object privileges
    """

    roles2 = []
    for uname in users:
        user = users[uname]
        for role in user.roles:
            if role not in roles2:
                roles2.append(role)
                if len(role.privileges) > 0:
                    print(f"!!! Role {getName(role.name)} with privileges + granted to user!")

def connect(connect_mode, account, user, role):
    
    # (a) connect to Snowflake with SSO
    if connect_mode == "SSO":
        return snowflake.connector.connect(
            account = account,
            user = user,
            role = role,
            authenticator = "externalbrowser"
        )

    # (b) connect to Snowflake with username/password
    if connect_mode == "PWD":
        return snowflake.connector.connect(
            account = account,
            user = user,
            role = role,
            password = os.getenv('SNOWFLAKE_PASSWORD')
        )

    # (c) connect to Snowflake with key-pair
    if connect_mode == "KEY-PAIR":
        with open(f"{str(Path.home())}/.ssh/id_rsa_snowflake_demo", "rb") as key:
            p_key= serialization.load_pem_private_key(
                key.read(),
                password = None, # os.environ['SNOWFLAKE_PASSPHRASE'].encode(),
                backend = default_backend()
            )
        pkb = p_key.private_bytes(
            encoding = serialization.Encoding.DER,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption())

        return snowflake.connector.connect(
            account = account,
            user = user,
            role = role,
            private_key = pkb
        )

def main():
    """
    Main entry point of the CLI
    """

    # read profiles_db.conf
    parser = configparser.ConfigParser()
    parser.read("profiles_db.conf")
    section = "default"
    account = parser.get(section, "account")
    user = parser.get(section, "user")
    role = parser.get(section, "role")

    # change this to connect in a different way: SSO / PWD / KEY-PAIR
    connect_mode = "PWD"
    con = connect(connect_mode, account, user, role)
    cur = con.cursor()

    options = Options()
    users = {}
    roles = {}
    objects = {}
    importMetadata(options, users, roles, objects, cur)
    con.close()

    filename = None

    if options.sepUsers != None:
        checkSeparateUsers(options, users)
    
    elif options.sepRoles != None:
        checkSeparateRoles(options, roles)
    
    elif options.checkRoles:
        # check two-layer roles
        checkRoles(options, users)

    elif options.user != None:
        # show user info
        if options.user not in users:
            print(f"??? User {options.user} not found!")
        else: 
            users[options.user].dumpRolesPrivs(options)
            filename = f"output/{account}-{options.user}"

    elif options.role != None:
        # show role info
        if options.role not in roles:
            print(f"??? Role {options.role} not found!")
        else:
            roles[options.role].dumpUsersRolesPrivs(options)
            filename = f"output/{account}-{options.role}"

    else:
        filename = f"output/{account}"

    if filename != None:
        saveDot(options, users, roles, objects, filename)

if __name__ == "__main__":
    main()
