# ITS
- ## Kennzeichen
	- Nachrichten/Daten werden für einen definierten Personenkreis verschlüsselt.
	- No shared secret
	- Private + zugehöriger public Key
	- Ermöglicht Digitale Signatur
	- Aufwändig/Laufzeitintensiv
- ## Schlüsselpaar
	- ### Private Key
		- Entschlüsseln von Nachrichten (Daten)
		- Digitale Signatur
		- Muss geschützt werden
			- Symmetrische verschlüsselung?
	- ### Public Key
		- Verschlüsseln von Nachrichten (Daten)
		- Verifikation von Signaturen
		- Verifikation der Integrität einer Nachricht (Daten)
		- Darf und **SOLL** veröffentlicht werden
	- ### Problem
		- Zuordnung zwischen realer Person und öffentlichem Schlüssel
- ## Verfahren
	- Teilnehmer benötigen Schlüsselpaar
	- Teilnehmer benötigen public Key des Empfängers bzw. des Autors der digitalen Signatur
	- Schlüsselpaar wird initial einmal generiert
	- Private Key muss behütet werden -> Darf nicht geleakt werden
	- Public Key kann öffentlich verteilt werden
- ![image.png](../assets/image_1722775736884_0.png)
	- ### Beispiel Verschlüsseln:
		- Datei `myfile` für Empfänger `blake@cyb.org`
		- Verschlüsselte Datei ist `myfile.gpg`
		- Datei kann nur von Private Key Besitzer entschlüsselt werden
		- Mehrere Empfänger möglich
		- `gpg` sucht mit Email in *Schlüsselring* nach zugehörigem **public key**
		-
		  ```shell
		  gpg --output myfile.gpg --encrypt myfile -r blake@cyb.org
		  ```
	- ### Entschlüsseln
		- Blake entschlüsselt `myfile.gpg`
		- Klartext wird in `myfile` abgelegt
		- Private Key der zu `blake@cyb.org` gehört wird benötigt
		- `gpg` sucht mit Email nach zugehörigem **private key**
		-
		  ```shell
		  gpg --output myfile --decrypt myfile.gpg
		  ```
- ## Erstellung von Schlüsselpaaren
	- ### openssl
		-
		  ```shell
		  // creates private key
		  openssl genrsa -out private.pem 2048
		  
		  // creates public key from private key
		  openssl rsa -pubout -in private.pem -out public.pem 
		  
		  // shows contents of key
		  openssl rsa -text -in private.pem
		  ```
	- ### gpg
		-
		  ```shell
		  gpg --gen-key
		  ```
- ## Digitale Unterschrift
	- *Klartext* wird mit **private Key** digital signiert
	- Signatur enthält Hashwert des Klartexts -> Ermöglicht Überprüfung des Originals
	- Signatur kann an Klartext angehängt -> Klartext + Signatur möglich
	- Oder Signatur als eigene Datei (abgetrennte Signatur)
	- ### Beispiel:
		- Versehe `myfile` mit abgetrennter Signatur in `myfile.sig`
		-
		  ```shell
		  gpg -a --sign --output myfile.sig --detach-sig myfile
		  ```
	- ### Überprüfung
		- Benötigt: abgetrennte Signatur + signierte Datei
			- Public Key des Signierenden benötigt
		- Mit *public key* des Signierenden und digitaler Unterschrift
			- -> überprüfen ob Datei `myfile` von Besitzer des public key stammt
			- -> überprüfen ob `myfile` nachträglich modifiziert wurde
		-
		  ```shell
		  gpg --verify myfile.sig myfile
		  ```
	- ## Fragen:
		- Alice möchte Bob und Carl verschlüsselte Mails schicken. Welche Schlüssel benötigt Alice, welche Bob und welche Carl?
			- **Alice**: Public Key von Bob und Carl (zum Verschlüsseln)
			- **Bob**: eigenen private key (zum Entschlüsseln)
			- **Carl**: eigenen private key
		- Alice möchte Bob und Carl *signierte, unverschlüsselte* Mails schicken. Welche Schlüssel benötigt Alice, welche Bob und Carl?
		- **Alice**: eigenen, private key (digital signature)
		- **Bob**: public key von Alice
		- **Carl**: public key von Alice
	- ## Zertifikate
		- Kombination aus
			- Public key
			- Identifikationsmerkmale (Meta-Informationen)
			- Digitale Unterschrift
		- wird **Zertifikat** genannt
- ## Echtheitsnachweis
	- ### Certificate Authority (CA)
		- Institution, die Zertifikate (vertrauenswürdig) signiert
	- ### Public Key Infrastructure (PKI)
		- Technische Umgebung zur **Erstellung, Signatur, Verteilung** und **Rückruf** von Zertifikaten
		- ### Vorgehen
			- Public-Key erstellen
			  logseq.order-list-type:: number
			- **Signing-Request** erstellen
			  logseq.order-list-type:: number
			- Public-Key + Metainformationen + Signing-Request an die CA übergeben
			  logseq.order-list-type:: number
			- CA prüft Echtheit
			  logseq.order-list-type:: number
			- CA signiert Zertifikat (als Issuer)
			  logseq.order-list-type:: number
			- CA verteilt Zertifikat
			  logseq.order-list-type:: number
		- (Weiteres:) Zertifikat zurückrufen (revoke)
	- ### Hierarchische PKI
		- Zentrale (vertrauenswürdige) Instanz signiert den public key
			- Certificate Authority
		- Bsp.: Verisign, Lets Encrypt
		- Email-Verschlüsselung über S/Mime
	- ### Web of Trust
		- Dezentrales Verfahren
		- Zertifikate bekommen mehrere Signaturen
			- Key-Signing-Parties
			- Jeder kann ein Zertifikat unterschreiben
			- Vertrauen kann über *Vertrauensketten* gestärkt werden
		- Echtheit wird über Vertrauensstufen realisiert
			- Hohe Vertrauensstufe bei vielen (vertrauenswürdigen Signaturen)
		- #### Beispiel Vertrauenskette
			- *Alice* signiert den Schlüssel von *Bob*
			- *Bob* signiert den Schlüssel von *Carl*
			- *Alice* vertraut damit auch *Carl*
	- ### Öffentliche PKI
		- Zentrale, öffentliche PKIs sind anfällig
		- Kann **keine** Sicherheit garantieren, da *Fremden* vertrauen geschenkt werden muss
		- HTTPS garantiert über öffentliche Zertifikate verschlüsselte Verbindungen -> ABER keine vertrauenswürdige Authentifizierung
	- ### Private CA's
		- CA's die intern (Unternehmen, privat) eingesetzt werden sind *sicher* -> Keinen Fremden muss getraut werden
			- Beispiel: OpenVPN-Zertifikate der HSNR
	- ## Certificate Revokation
		- Zertifikate haben Gültigkeit (von, bis)
		- Ist der private key zu einem Zertifikat verloren muss das Zertifikat zurückgerufen werden (revoked)
		- public key -> als ungültig markiert
		- Rückruf in *öffentliche* Rückrufliste (Revocationlist) eingetragen
		- Prüfende Instanz muss Revocationlist abfragen (Online-Verbindung notwendig)
		- *Revocation Certificate* als Legimitation für Rückruf -> Agiert ähnlich zu einem private key (??)
		- ### Prüfungsfrage: Unter welchen Umständen ist eine ÖFFENTLICHE PKI sicher?
			- Wenn der private key der CA SICHER aufbewahrt wird
			  logseq.order-list-type:: number
			- Wenn sichergestellt, dass public key wirklich von der CA stammt
			  logseq.order-list-type:: number
			- Wenn Mitarbeiter der CA Organisation vertrauenswürdig sind
			  logseq.order-list-type:: number
		- => Also **NIE**
		- ### Prüfungsfrage: Unter welchen Umständen ist eine PKI sicher?
			- Wenn sie selbst betrieben wird
			- Wenn der private Key der CA **sicher** aufbewahrt wird
			- Wenn Mitarbeiter vertrauenswürdig sind
- ## Datenverschlüsselung
	- Das Datenschutzgesetz verpflichtet uns in vielen Fällen sensible Informationen vor unberechtigtem Zugriff zu schützen
	- => Datenverschlüsselung
	- ### Varianten
		- Verschlüsselung von einzelnen Dateien
		  logseq.order-list-type:: number
		- Komplettverschlüsselung eines Datenträgers (Blockgerät)
		  logseq.order-list-type:: number
		- Partielle Verschlüsselung: Schützenswerte Dateien werden verschlüsselt und in *harmlosen* Dateien versteckt
		  logseq.order-list-type:: number
			- => enthält real ein komplettes, verschlüsseltes Filesystem
			  logseq.order-list-type:: number
	- ### Software
		- PGP zur Verschlüsselung von einzelnen Dateien oder auch E-Mails
		- VeraCrypt zur Verschlüsselung von Datenträgern
		-
	-
	-
