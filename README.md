Snowflake RBAC Inspector
========================

A small utility tool in Python to verify and render nice diagrams with roles and privileges from a whole Snowflake account.

Beside the on-screen information, the tool may generate graphs in the output/ folder, as DOT and HTML files. We recommend to visualize directly the HTML files in your browser. The DOT files are just an alternative, to be used with either a **Graphviz Preview** VSC extension - alongside the **Graphviz (dot) language support ...** extension - or with a free online visualizer like [viz-js.com](http://viz-js.com/).

# Database Profile File

Create a **profiles_db.conf** copy of the **profiles_db_template.conf** file, and customize it with your own Snowflake connection parameters. Your top [default] profile is the active profile, considered by our tool. Below you may define other personal profiles, that you may override under [default] each time you want to change your active connection.

We connect to Snowflake with the Snowflake Connector for Python. We have code for (a) password-based connection, (b) connecting with a Key Pair, and (c) connecting with SSO. For password-based connection, save your password in a SNOWFLAKE_PASSWORD local environment variable. Never add the password or any other sensitive information to your code or to profile files. All names must be case sensitive, with no quotes.

We always collect RBAC-related data from the whole Snowflake account, so do not specify a database or a schema in the profile file. Also, while all collected data is metadata, there is no need for a virtual warehouse.

# CLI Executable File

You can invoke the tool directly from a Terminal window in Visual Source Code, as it follows:

**<code>python rbac-inspector.py [options]</code>**  

Calling with no options will show you what commands are available:

* Usage: python database-inspector.py [options]  
* --sepusers user1 user2 ...         - verifies that listed users access different objects  
* --seproles role1 role2 ...         - verifies that listed roles access different objects  
* --checkroles                       - verifies that we have a two-layer role hierarchy  
* --user user1                       - show inherited roles and privileges only for a user  
* --role role1                       - show inherited roles and privileges only for a role  
* --users                            - show user objects  
* --roles                            - show role objects  
* --sysroles                         - include the system roles  
* --types warehouse schema ...       - the types of objects to include (all if empty)  
* --privs usage manage_grants ...    - the types of privileges (all if empty)  
* --compact                          - compact display (by default per inherited role)  

To compile into a CLI executable:

**<code>pip install pyinstaller</code>**  
**<code>pyinstaller --onefile rbac-inspector.py</code>**  
**<code>dist/rbac-inspector [options]</code>**  

# Example Usage

**<code>python rbac-inspector.py --sepusers USER1 USER2 --compact</code>**

Verifies that the USER1 and USER2 users cannot access the same objects, or shows the object they can access. And shows their object privileges in a compact manner. No file is generated.

**<code>python rbac-inspector.py --seproles ROLE1 ROLE2</code>**

Verifies that the ROLE1 and ROLE2 roles, including their inherited roles, cannot access the same objects, or shows the object they can access. And shows their object privileges per inherited role. No file is generated.

**<code>python rbac-inspector.py --checkroles</code>**

Verifies that we have a two-layer role hierarchy, as best practice. Top roles can be only granted to users, while lower roles have object privileges granted to them. If not, shows roles with both privileges and assigned to users. No file is generated.

**<code>python rbac-inspector.py --user USER1 --types</code>**

Show all roles and object privileges for the USER1 user, layered by each granted role. Generates DOT and HTML files with the account and user name to visualize this in Graphviz.

**<code>python rbac-inspector.py --role ROLE1</code>**

Show all inherited roles of the ROLE1 role, with nothing else (no object privileges). Generates DOT and HTML files with the account and role name to visualize this in Graphviz.

**<code>python rbac-inspector.py --role ROLE1 --types --compact</code>**

Show all object privileges for the ROLE1 role, in a compact manner, with all inherited roles on top. Generates DOT and HTML files with the account and role name to visualize this in Graphviz. Example:

![Role Privileges](/images/account-ROCKETSHIP_ADMINISTRATOR.png)

**<code>python rbac-inspector.py --role ROLE1 --types</code>**

Show all roles and object privileges for the ROLE1 role, layered by each inherited role. Generates DOT and HTML files with the account and role name to visualize this in Graphviz.

**<code>python rbac-inspector.py --roles</code>**

Show the whole hierarchy of roles, with nothing else. Generates DOT and HTML files with the account name to visualize this in Graphviz. Example:

![Role Hierarchy](/images/account.png)

**<code>python rbac-inspector.py --roles --types warehouse</code>**

Show privileges on virtual warehouses granted to roles. Generates DOT and HTML files with the account name to visualize this in Graphviz.

**<code>python rbac-inspector.py --users --roles --sysroles --types warehouse database schema</code>**

Show users and object privileges for virtual warehouses, databases and schemas, including roles with system roles. Generates DOT and HTML files with the account name to visualize this in Graphviz.

**<code>python rbac-inspector.py --roles --types account --privs manage_grants</code>**

Show roles and only MANAGE GRANTS ON ACCOUNT privileges (use underscore when the privilege name has a space). Generates DOT and HTML files with the account name to visualize this in Graphviz.

**<code>python rbac-inspector.py --roles --types database --privs ownership</code>**

Show only OWNERSHIP privileges for databases to roles. Generates DOT and HTML files with the account name to visualize this in Graphviz.

# RBAC Hierarchies

Another simple script will save the role and user hierarchies from a Snowflake account, using a different approach. The following call will generate in the output/ folder DOT and HTML files with -users and -roles suffixes:

**<code>python rbac-hierarchies.py</code>**

The role hierarchy:

![Roles Hierarchy](/images/account-roles.png)

The user-role hierarchy:

![Users Hierarchy](/images/account-users.png)