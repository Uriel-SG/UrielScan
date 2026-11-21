# UrielScan - Free Open Source Net-Generation Vulnerabliity Scanner

## Scopo del progetto

Ad oggi, i vulnerability scanner di qualità, o sono a pagamento, o sono "complessi" da configurare. Inoltre vi sono scanner ottimizzati per le web application e scanner ottimizzati per le network. 

UrielScan deve essere uno scanner delle vulnerabilità per Purple Team ottimizzato sia per le vulnerabilità di rete, sia per quelle delle web application. 
UrielScan deve essere estremamente semplice da installare, ma anche estremamente user friendly: una volta avviato, è possibile accederci tramite web browser e gestirlo in maniera semplificata con la sua interfaccia moderna, animata, efficiente, completa e comprensibile.

## Come costruirlo facilmente?

Io proporrei di sfruttare elementi di altri tool open source già disponibili, mettendoli insieme e potenziando/migliorando ciò che si può potenziare migliorare, oltre che aggiungere quello che manca. 

## Compatibilità

Deve essere eseguibile sia su linux sia su windows.
In entrambi i casi deve poter prevedere una schedulazione eventuale delle scansioni (se abilitata)

## Ispirazioni

Sicuramente nmap, con le sue potenzialità anche lato NSE: sarebbe straordinario avere un'interfaccia grafica moderna, superiore anche all'obsoleta ormai ZenMap;
Sicuramente nuclei, come scanner web straordinario assieme ai suoi moduli potenti;
Infine: openVAS e OWASP Zap, strumenti validissimi.

## Importante

Rispetto agli altri Vulnerablity Scanner, UrielScan deve avere la possibilità di integrazione con un'AI tramite API. l'AI può analizzare i risultati delle scansioni su richiesta, o di tutta la scansione o di alcune sue parti; l'AI può inoltre generare il report finale in base alle info dell'azienda che fa lo scan e l'azienda che lo riceve;

## Personalizzazione

Chiunque deve avere la possibilità di caricare il proprio logo. Inoltre UrielScan deve essere adatto agli MSP e agli MSSP, con la possibilità di creare diverse organizzazioni.

Buon lavoro!
