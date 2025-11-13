``` mermaid
graph TD
    subgraph Internet
        CloudEmail[Cloud Email Service]
    end

    subgraph Office Network
        Router[Network Router]
        Firewall[Firewall]
        Server[Application Server]
        DB[Database Server]
        Employee1[Employee Workstation 1]
        Employee2[Employee Workstation 2]
    end

    CloudEmail --> Router
    Router --> Firewall
    Firewall --> Server
    Firewall --> DB
    Firewall --> Employee1
    Firewall --> Employee2

