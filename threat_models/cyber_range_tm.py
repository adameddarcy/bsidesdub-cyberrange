#!/usr/bin/env python3
"""
Cyber Range Threat Model
========================
pytm threat model for the three-tier cyber range workshop environment.

Usage:
    ./cyber_range_tm.py --dfd | dot -Tpng -o output/dfd.png
    ./cyber_range_tm.py --seq | java -Djava.awt.headless=true -jar plantuml.jar -tpng -pipe > output/seq.png
    ./cyber_range_tm.py --report docs/template.md | pandoc -f markdown -t html > output/report.html
"""

from pytm import (
    TM,
    Actor,
    Boundary,
    Dataflow,
    Datastore,
    Server,
    Process,
    Data,
    Classification,
    ExternalEntity,
)

tm = TM("Cyber Range Threat Model")
tm.description = """
Three-tier cyber range environment for threat modelling workshops.
Includes intentionally vulnerable components for STRIDE analysis training.
"""
tm.isOrdered = True
tm.mergeResponses = True


internet = Boundary("Internet")
dmz = Boundary("DMZ Network (10.10.1.0/24)")
app_net = Boundary("App Network (10.10.2.0/24)")
internal_net = Boundary("Internal Network (10.10.3.0/24)")
monitoring_net = Boundary("Monitoring Network (10.10.4.0/24)")


user = Actor("Internet User")
user.inBoundary = internet

analyst = Actor("Workshop Analyst")
analyst.inBoundary = internet
analyst.isAdmin = False

attacker = Actor("Attacker")
attacker.inBoundary = internet


proxy = Server("nginx Proxy")
proxy.OS = "Alpine Linux"
proxy.inBoundary = dmz
proxy.isHardened = False
proxy.sanitizesInput = False
proxy.implementsAuthenticationScheme = False
proxy.hasAccessControl = False

juiceshop = Server("OWASP Juice Shop")
juiceshop.OS = "Node.js"
juiceshop.inBoundary = dmz
juiceshop.isHardened = False
juiceshop.sanitizesInput = False
juiceshop.implementsAuthenticationScheme = True
juiceshop.hasAccessControl = True
juiceshop.checksInputBounds = False

bastion = Server("Bastion SSH")
bastion.OS = "Linux"
bastion.inBoundary = dmz
bastion.isHardened = False
bastion.implementsAuthenticationScheme = True
bastion.hasAccessControl = True


internal_api = Server("httpbin API")
internal_api.OS = "Python"
internal_api.inBoundary = app_net
internal_api.isHardened = False
internal_api.implementsAuthenticationScheme = False
internal_api.hasAccessControl = False
internal_api.sanitizesInput = False

agent = Server("Agent Service")
agent.OS = "Python 3.12"
agent.inBoundary = app_net
agent.isHardened = False
agent.implementsAuthenticationScheme = False
agent.hasAccessControl = False
agent.sanitizesInput = False
agent.checksInputBounds = False
agent.usesEnvironmentVariables = True


db = Datastore("MySQL Database")
db.OS = "MySQL 8.0"
db.inBoundary = internal_net
db.isHardened = False
db.isSQL = True
db.isShared = True
db.hasWriteAccess = True
db.storesLogData = True
db.storesPII = True
db.isEncryptedAtRest = False

ldap = Datastore("OpenLDAP")
ldap.OS = "OpenLDAP"
ldap.inBoundary = internal_net
ldap.isHardened = False
ldap.hasWriteAccess = True
ldap.storesPII = True
ldap.implementsAuthenticationScheme = False


loki = Server("Loki Log Aggregator")
loki.OS = "Grafana Loki"
loki.inBoundary = monitoring_net
loki.isHardened = True

promtail = Process("Promtail Log Shipper")
promtail.inBoundary = monitoring_net

grafana = Server("Grafana Dashboard")
grafana.OS = "Grafana"
grafana.inBoundary = monitoring_net
grafana.implementsAuthenticationScheme = False
grafana.hasAccessControl = False


http_request = Data(
    name="HTTP Request",
    description="User HTTP request to web application",
    classification=Classification.PUBLIC,
    isPII=False,
    isCredentials=False,
)

user_credentials = Data(
    name="User Credentials",
    description="Username and password for authentication",
    classification=Classification.SECRET,
    isPII=True,
    isCredentials=True,
)

jwt_token = Data(
    name="JWT Token",
    description="JWT authentication token (weak secret: 'secret')",
    classification=Classification.SENSITIVE,
    isPII=False,
    isCredentials=True,
)

sql_query = Data(
    name="SQL Query",
    description="Database query potentially containing user input",
    classification=Classification.SENSITIVE,
    isPII=False,
)

pii_data = Data(
    name="PII Records",
    description="Personally identifiable information from database",
    classification=Classification.SECRET,
    isPII=True,
)

agent_prompt = Data(
    name="Agent Prompt",
    description="LLM prompt including injectable context field",
    classification=Classification.SENSITIVE,
    isPII=False,
)

tool_output = Data(
    name="Tool Output",
    description="Unsanitised output from agent tool execution",
    classification=Classification.SENSITIVE,
    isPII=False,
)

ldap_query = Data(
    name="LDAP Query",
    description="Directory query (anonymous bind enabled)",
    classification=Classification.PUBLIC,
)

log_data = Data(
    name="Log Data",
    description="Application and container logs including sensitive queries",
    classification=Classification.SENSITIVE,
    isPII=False,
)

ssh_session = Data(
    name="SSH Session",
    description="SSH connection with password authentication",
    classification=Classification.SENSITIVE,
    isCredentials=True,
)


user_to_proxy = Dataflow(user, proxy, "HTTP Request")
user_to_proxy.protocol = "HTTP"
user_to_proxy.dstPort = 80
user_to_proxy.data = http_request
user_to_proxy.isEncrypted = False

proxy_to_juiceshop = Dataflow(proxy, juiceshop, "Proxied Request")
proxy_to_juiceshop.protocol = "HTTP"
proxy_to_juiceshop.dstPort = 3000
proxy_to_juiceshop.data = http_request

juiceshop_to_proxy = Dataflow(juiceshop, proxy, "HTTP Response")
juiceshop_to_proxy.protocol = "HTTP"
juiceshop_to_proxy.data = http_request

proxy_to_user = Dataflow(proxy, user, "HTTP Response")
proxy_to_user.protocol = "HTTP"
proxy_to_user.data = http_request
proxy_to_user.isEncrypted = False

analyst_to_bastion = Dataflow(analyst, bastion, "SSH Connection")
analyst_to_bastion.protocol = "SSH"
analyst_to_bastion.dstPort = 2222
analyst_to_bastion.data = ssh_session
analyst_to_bastion.isEncrypted = True

bastion_to_analyst = Dataflow(bastion, analyst, "SSH Response")
bastion_to_analyst.protocol = "SSH"
bastion_to_analyst.data = ssh_session
bastion_to_analyst.isEncrypted = True

bastion_to_agent = Dataflow(bastion, agent, "Agent Invocation")
bastion_to_agent.protocol = "HTTP"
bastion_to_agent.dstPort = 5000
bastion_to_agent.data = agent_prompt

agent_to_bastion = Dataflow(agent, bastion, "Agent Response")
agent_to_bastion.protocol = "HTTP"
agent_to_bastion.data = tool_output

bastion_to_api = Dataflow(bastion, internal_api, "API Request")
bastion_to_api.protocol = "HTTP"
bastion_to_api.dstPort = 80
bastion_to_api.data = http_request

api_to_bastion = Dataflow(internal_api, bastion, "API Response")
api_to_bastion.protocol = "HTTP"
api_to_bastion.data = http_request

bastion_to_db = Dataflow(bastion, db, "MySQL Query")
bastion_to_db.protocol = "MySQL"
bastion_to_db.dstPort = 3306
bastion_to_db.data = sql_query

db_to_bastion = Dataflow(db, bastion, "Query Results")
db_to_bastion.protocol = "MySQL"
db_to_bastion.data = pii_data

bastion_to_ldap = Dataflow(bastion, ldap, "LDAP Query")
bastion_to_ldap.protocol = "LDAP"
bastion_to_ldap.dstPort = 389
bastion_to_ldap.data = ldap_query

ldap_to_bastion = Dataflow(ldap, bastion, "LDAP Response")
ldap_to_bastion.protocol = "LDAP"
ldap_to_bastion.data = pii_data


juiceshop_to_db = Dataflow(juiceshop, db, "SQL Query (as root)")
juiceshop_to_db.protocol = "MySQL"
juiceshop_to_db.dstPort = 3306
juiceshop_to_db.data = sql_query
juiceshop_to_db.sanitizedInput = False

db_to_juiceshop = Dataflow(db, juiceshop, "Query Results")
db_to_juiceshop.protocol = "MySQL"
db_to_juiceshop.data = pii_data


agent_to_api = Dataflow(agent, internal_api, "Tool Call (SSRF)")
agent_to_api.protocol = "HTTP"
agent_to_api.dstPort = 80
agent_to_api.data = agent_prompt
agent_to_api.sanitizedInput = False

api_to_agent = Dataflow(internal_api, agent, "Tool Response")
api_to_agent.protocol = "HTTP"
api_to_agent.data = tool_output

agent_to_db = Dataflow(agent, db, "Database Tool Call")
agent_to_db.protocol = "MySQL"
agent_to_db.dstPort = 3306
agent_to_db.data = sql_query

db_to_agent = Dataflow(db, agent, "Database Results")
db_to_agent.protocol = "MySQL"
db_to_agent.data = pii_data

agent_to_ldap = Dataflow(agent, ldap, "LDAP Enumeration")
agent_to_ldap.protocol = "LDAP"
agent_to_ldap.dstPort = 389
agent_to_ldap.data = ldap_query

ldap_to_agent = Dataflow(ldap, agent, "Directory Data")
ldap_to_agent.protocol = "LDAP"
ldap_to_agent.data = pii_data


promtail_to_loki = Dataflow(promtail, loki, "Log Ingestion")
promtail_to_loki.protocol = "HTTP"
promtail_to_loki.dstPort = 3100
promtail_to_loki.data = log_data

loki_to_grafana = Dataflow(loki, grafana, "Log Query Results")
loki_to_grafana.protocol = "HTTP"
loki_to_grafana.data = log_data

analyst_to_grafana = Dataflow(analyst, grafana, "Dashboard Access")
analyst_to_grafana.protocol = "HTTP"
analyst_to_grafana.dstPort = 3000
analyst_to_grafana.data = log_data
analyst_to_grafana.isEncrypted = False

grafana_to_analyst = Dataflow(grafana, analyst, "Dashboard View")
grafana_to_analyst.protocol = "HTTP"
grafana_to_analyst.data = log_data


attacker_to_proxy = Dataflow(attacker, proxy, "Malicious HTTP Request")
attacker_to_proxy.protocol = "HTTP"
attacker_to_proxy.dstPort = 80
attacker_to_proxy.data = http_request

attacker_to_bastion = Dataflow(attacker, bastion, "SSH Brute Force")
attacker_to_bastion.protocol = "SSH"
attacker_to_bastion.dstPort = 2222
attacker_to_bastion.data = ssh_session


if __name__ == "__main__":
    tm.process()
