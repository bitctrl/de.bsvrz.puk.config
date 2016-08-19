/*
 * Copyright 2006 by Kappich Systemberatung Aachen
 * 
 * This file is part of de.bsvrz.puk.config.
 * 
 * de.bsvrz.puk.config is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * de.bsvrz.puk.config is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with de.bsvrz.puk.config.  If not, see <http://www.gnu.org/licenses/>.

 * Contact Information:
 * Kappich Systemberatung
 * Martin-Luther-Straße 14
 * 52062 Aachen, Germany
 * phone: +49 241 4090 436 
 * mail: <info@kappich.de>
 */
package de.bsvrz.puk.config.main.authentication;

import de.bsvrz.dav.daf.communication.srpAuthentication.SrpVerifierAndUser;
import de.bsvrz.dav.daf.main.DataAndATGUsageInformation;
import de.bsvrz.dav.daf.main.config.ConfigurationTaskException;
import de.bsvrz.dav.daf.main.impl.config.request.RequestException;
import de.bsvrz.sys.funclib.dataSerializer.Deserializer;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Collection;
import java.util.List;

/**
 * Dieses Interface stellt Methoden zur Verfügung, mit der sich ein Benutzer Authentifizieren und Verwaltungsaufgaben
 * anstossen kann.
 * <p>
 * Die Methode {@link #isValidUser} prüft ob eine übergebene Benutzer/Passwort kombination gültig ist.
 * <p>
 * Die Methode {@link #processTask} beauftragt die Konfiguration eine der folgenden Aufträge auszuführen:<br> - Neuer
 * Benutzer anlegen<br> - Einmal-Passwort erzeugen<br> - Rechte eines Benutzers ändern<br> - Passwort eines Benuzters
 * ändern<br>
 * <p>
 * Alle Informationen die für die oben genannten Aufgaben benötigt werden, werden verschlüsselt übertragen.
 * <p>
 * Die Methode {@link #getText} liefert einen Zufallstext. Der Zufallstext wird beöntigt um "Reply-Attacken"
 * (verschicken von Kopien bestimmter Telegramme) zu verhindern. Dieser Text muss in allen Telegrammen, die für die
 * {@link #processTask} Methode benötigt werden, verschlüsselt übertragen werden. Danach darf der verschlüsselt
 * übertragenen Text nicht mehr für andere Aufgaben funktionieren.
 *
 * @author Achim Wullenkord (AW), Kappich Systemberatung
 * @version $Revision:5077 $ / $Date:2007-09-02 14:48:31 +0200 (So, 02 Sep 2007) $ / ($Author:rs $)
 */
public interface Authentication {
	/**
	 * Die Implementierung dieser Methode stellt die Authentifizierung des Benutzers sicher. Dafür wird das original
	 * Passwort mit dem übergebenen <code>authentificationText</code> verschlüsselt und mit dem übergebenen verschlüsselten
	 * Passwort verglichen. Sind beide Passwörter gleich, und der übergebene Benutzername stimmt mit dem Benutzernamen des
	 * original Passworts überein, so war die Authentifkation erfolgreich.
	 * <p>
	 * Konnte das original Passwort nicht benutzt werden, muss geprüft werden, ob es ein Einmal-Passwort gibt. Das
	 * Einmal-Passwort muss das derzeit aktuell gültige sein und muss mit dem übergebenen verschlüsseltem Passwort
	 * übereinstimmen. Gibt es ein entsprechendes Einmal-Passwort, so ist es für immer zu sperren.
	 * <p>
	 * Konnte kein Passwort gefunden werden, wird eine IllegalArgumentException geworfen.
	 *
	 * @param username                    Benutzername, der zu dem übergebenen verschlüsselten Passwort gehört
	 * @param encryptedPassword           Passwort, das mit dem übergebenen Text <code>authentificationText</code> verschlüsselt wurde
	 * @param authentificationText        Text, der benutzt wurde um das übergebene Passwort <code>encryptedPassword</code> zu verschlüsseln
	 * @param authentificationProcessName Name des Verschlüsslungsverfahren, das benutzt wurde. Mit diesem Verfahren wird das Originalpasswort verschlüsselt
	 * @throws Exception                Fehler beim schreiben der neuen Informationen oder ein technisches Problem beim verschlüsseln der Daten
	 * @throws IllegalArgumentException Dem Benutzernamen konnte das Passwort nicht zugeordnet werden oder der Benutzer war unbekannt
	 * @deprecated Diese Methode wird von der alten HMAC-Authentifizierung ohne Verschlüsselung benutzt
	 */
	@Deprecated
	public void isValidUser(String username, byte[] encryptedPassword, String authentificationText, String authentificationProcessName) throws Exception, IllegalArgumentException;

	/**
	 * Bearbeitet eine der folgenden Aufgaben:<br> - Neuer Benutzer anlegen<br> - Einmal-Passwort erzeugen<br> - Rechte eines Benutzers ändern<br> - Passwort
	 * eines Benutzers ändern<br> - Anzahl der Einmalpasswörter ermitteln<br> - Einmalpasswörter löschen<br> - Benutzer löschen<br> - Abfrage nach Existenz und
	 * Adminstatus eines Benutzers
	 *
	 * @param usernameCustomer      Benutzer, der den Auftrag erteilt
	 * @param encryptedMessage      verschlüsselte Aufgabe, die ausgeführt werden soll
	 * @param encryptionProcessName Verschlüsslungsverfahren mit der <code>encryptedMessage</code> erstellt wurde
	 * @return Rückmeldung der durchgeführten Aufgabe, beispielsweise die Anzahl der verbleibenden Einmalpasswörter, falls danach gefragt wurde. -1 bei Aufgaben
	 * ohne Rückgabewert.
	 * @throws ConfigurationTaskException Der Auftrag, der durch die Konfiguration ausgeführt werden sollte, konnte nicht durchgeführt werden, weil bestimmte
	 *                                    Parameter nicht erfüllt waren. Welche Parameter dies genau sind, hängt vom jeweiligen Auftrag ab, so kann zum Beispiel
	 *                                    ein Passwort fehlerhaft gewesen sein oder der Benutzer besitzt nicht die nötigen Rechte um einen Auftrag dieser Art
	 *                                    anzustoßen. Wenn der Auftrag erneut übermittelt werden würde, mit den richtigen Parametern, könnte er ausgeführt
	 *                                    werden.
	 * @throws RequestException           Der Auftrag konnte aufgrund eines technischen Fehlers nicht ausgeführt werden (defektes Speichermedium, Fehler im
	 *                                    Dateisystem, usw.). Erst wenn dieser Fehler behoben ist, können weitere Aufträge ausgeführt werden.
	 * @deprecated Diese Methode wird von der alten HMAC-basierten Benutzerverwaltung benutzt und ist bei SRP nicht mehr sinnvoll. Diese Methode funktioniert
	 * nur, wenn das Passwort im Klartext gespeichert ist.
	 */
	@Deprecated
	public int processTask(String usernameCustomer, byte[] encryptedMessage, String encryptionProcessName) throws ConfigurationTaskException, RequestException;

	/**
	 * Erzeugt einen Zufallstext und gibt diesen als Byte-Array zurück.
	 *
	 * @return Zufallstext
	 * @deprecated Diese Methode wird von der alten HMAC-basierten Benutzerverwaltung benutzt und ist bei SRP nicht mehr sinnvoll.
	 */
	@Deprecated
	public byte[] getText();

	/**
	 * Diese Methode wird aufgerufen, wenn das System heruntergefahren wird. Es ist ein Zustand herzustellen, der es ermöglicht das System wieder zu starten.
	 */
	public void close();

	/**
	 * Erstellt einen neuen Benutzer
	 * @param usernameCustomer Auftraggeber
	 * @param deserializer Serialisierte Daten zu dem Benutzer
	 * @throws ConfigurationTaskException
	 * @throws RequestException
	 * @throws IOException
	 */
	void createNewUser(String usernameCustomer, Deserializer deserializer) throws ConfigurationTaskException, RequestException, IOException;

	/**
	 * Prüft, ob ein Benutzer existiert
	 * @param userToCheck Benutzername
	 * @return true wenn er existiert, sonst false
	 */
	boolean isUser(String userToCheck);

	/**
	 * Löscht für einen angegebenen Benutzer alle Einmalpasswörter bzw. markiert diese als ungültig. Nur ein Admin und der Benutzer selbst darf diese Aktion ausführen.
	 * @param orderer Der Auftraggeber der Aktion
	 * @param username Der Benutzer, dessen Einmalpasswörter gelöscht werden sollen
	 * @throws FileNotFoundException
	 * @throws ConfigurationTaskException
	 */
	void clearSingleServingPasswords(String orderer, String username)
			throws FileNotFoundException, ConfigurationTaskException;

	/**
	 * Zählt die verbleibenden Einmalpasswörter für einen angegeben Benutzer. Nur ein Admin und der Benutzer selbst darf diese Aktion ausführen.
	 * @param orderer Der Auftraggeber der Aktion
	 * @param username Der Benutzer, dessen Einmalpasswörter gezählt werden sollen
	 * @return Die Anzahl der verbliebenen Einmalpasswörter
	 * @throws FileNotFoundException
	 * @throws ConfigurationTaskException
	 */
	int countRemainingSingleServingPasswords(String orderer, String username)
			throws FileNotFoundException, ConfigurationTaskException;

	/**
	 * Gibt die verbleibenden gültigen Einmalpasswort-IDs für einen angegeben Benutzer zurück. Nur ein Admin und der Benutzer selbst darf diese Aktion ausführen.
	 * @param orderer Der Auftraggeber der Aktion
	 * @param username Der Benutzer, dessen Einmalpasswörter gezählt werden sollen
	 * @return Die IDs der verbliebenen Einmalpasswörter
	 * @throws FileNotFoundException
	 * @throws ConfigurationTaskException
	 */
	int[] getRemainingSingleServingPasswordIDs(String orderer, String username)
			throws FileNotFoundException, ConfigurationTaskException;

	/**
	 * Prüft ob ein Benutzer Adminrechte hat. Jeder Benutzer darf diese Aktion ausführen.
	 * @param orderer Der Auftraggeber der Aktion. Wird in dieser Funktion derzeit nicht berücksichtigt, da jeder diese Abfrage ausführen darf
	 * @param userToCheck Der Benutzer, dessen Rechte geprüft werden sollen.
	 * @return True falls der Benutzer ein Admin ist
	 * @throws ConfigurationTaskException Der Auftrag kann nicht ausgeführt werden, weil der Benutzer nicht existiert
	 */
	boolean isUserAdmin(String orderer, String userToCheck) throws ConfigurationTaskException;

	/**
	 * @param username                      Benutzer, der den Auftrag angestossen hat
	 * @param usernameSingleServingPasswort Benutzer für den das Einmal-Passwort gedacht ist
	 * @param passwortSingleServingPasswort Einmal-Passwort
	 *
	 * @throws RequestException           Technischer Fehler, der Auftrag konnte nicht bearbeitet werden.
	 * @throws ConfigurationTaskException Die Konfiguration weigert sich den Auftrag auszuführen weil z.b. das Passwort falsch war, der Benutzer nicht die nötigen
	 *                                    Rechte besitzt usw..
	 */
	void createSingleServingPassword(String username, String usernameSingleServingPasswort, String passwortSingleServingPasswort)
			throws RequestException, ConfigurationTaskException;

	/**
	 * Legt einen neuen Benutzer mit den übergebenen Parametern an.
	 *
	 * @param username          Benutzer, der den Auftrag erteilt
	 * @param newUserName       Name des neuen Benutzers
	 * @param newUserPassword   Passwort des neuen Benutzers
	 * @param admin             Rechte des neuen Benutzers (true = Adminrechte; false = normaler Benutzerrechte)
	 * @param newUserPid        Pid, die der neue Benutzer erhalten soll. Wird ein Leerstring ("") übergeben, so bekommt der Benutzer keine expliziete Pid
	 * @param configurationArea Pid des Konfigurationsbereichs, in dem der neue Benutzer angelegt werden soll
	 * @param data              Konfigurierende Datensätze, die angelegt werden sollen (falls leere Liste oder <code>null</code> werden keine Daten angelegt)
	 *
	 * @throws ConfigurationTaskException Der neue Benutzer durfte nicht anglegt werden (Keine Rechte, Bentuzer bereits vorhanden)
	 * @throws RequestException           technischer Fehler beim Zugriff auf die XML-Datei
	 *
	 * @see de.bsvrz.dav.daf.main.config.ConfigurationArea#createDynamicObject(de.bsvrz.dav.daf.main.config.DynamicObjectType, String, String, java.util.Collection)
	 */
	void createNewUser(String username, String newUserName, String newUserPid, String newUserPassword, boolean admin, String configurationArea, Collection<DataAndATGUsageInformation> data)
			throws ConfigurationTaskException, RequestException;

	/**
	 * Setzt bei einem Benutzer das Passwort neu. Dies kann entweder ein Admin bei einem anderen Benutzerkonto oder ein Benutzer bei seinem eigenen Benutzerkonto.
	 * <p>
	 * Ist für einen Benutzer nur das Objekt des Benutzers in der Konfiguration vorhanden, aber das Benutzerkonto fehlt, wird das Benutzerkonto mit {@link
	 * #createNewUser} angelegt. Das neue Benutzerkonto besitzt dabei keine Adminrechte. Das neue Benutzerkonto wird dabei das Passwort erhalten, das neu gesetzt
	 * werden sollte.
	 * <p>
	 * Gibt es zwar ein Benutzerkonto, aber kein Objekt in der Konfiguration, wird ein Fehler ausgegeben.
	 * <p>
	 * Sind weder Objekt noch Benutzerkonto vorhanden wird ein Fehler ausgegeben.
	 *
	 * @param username                  Benutzer, der den Auftrag zum ändern des Passworts erteilt hat
	 * @param userNameForPasswordChange Benutzer, dessen Passwort geändert werden soll
	 * @param newPassword               neues Passwort
	 *
	 * @throws ConfigurationTaskException Der Benutzer ist unbekannt oder es gibt zu dem Benutzer kein entsprechendes Objekt oder der Benutzer darf das Passwort
	 *                                    nicht ändern (kein Admin oder der Besitzer des Passwords).
	 * @throws RequestException           Fehler beim Zugriff auf die XML-Datei
	 */
	void changeUserPassword(String username, String userNameForPasswordChange, String newPassword) throws ConfigurationTaskException, RequestException;

	/**
	 * @param username             Benutzer, der den Auftrag erteilt hat (dieser muss Adminrechte besitzen)
	 * @param usernameChangeRights Benutzer, dessen Rechte geändert werden soll
	 * @param newUserRights        Neue Rechte des Benutzers (true = Admin-Rechte, false = normaler Benutzerrechte
	 *
	 * @throws ConfigurationTaskException Der Benutzer ist unbekannt oder der Auftraggeber besitzt nicht die nötigen Rechte
	 * @throws RequestException           Fehler beim Zugriff auf die XML-Datei
	 */
	void changeUserRights(String username, String usernameChangeRights, boolean newUserRights) throws ConfigurationTaskException, RequestException;

	/**
	 * Löscht einen angegebenen Benutzer. Diese Aktion kann nur von Administratoren ausgeführt werden.
	 * @param username Veranlasser der Aktion
	 * @param userToDelete Benutzername des Benutzers, der gelöscht werden soll
	 * @throws RequestException Das Löschen kann aufgrund eines Problems nicht durchgeführt werden
	 * @throws ConfigurationTaskException Die Anfrage ist fehlerhaft weil der Veranlasser nicht die nötigen Rechte hat oder der zu löschende Benutzer nicht existiert
	 */
	void deleteUser(String username, String userToDelete) throws  RequestException , ConfigurationTaskException;

	/**
	 * Gibt die dem angegebenen Benutzer den gespeicherten SRP-Überprüfungscode (Verifier, v) zurück, mit dem jemand überprüfen kann, ob der Benutzer sein Passwort weiß, ohne das der
	 * überprüfende selbst das Passwort wissen muss.
	 * @param authenticatedUser Benutzer, der die Anfrage durchführt. Die Anfrage dürfen nur Administratioren durchführen, andere Benutzer dürfen nur für sich selbst den
	 *                          Verifier abfragen.   
	 * @param username          Benutzername, dessen SRP-Verifier abgefragt wird    
	 * @param passwordIndex
	 * @return Überprüfungscode und Meta-Informationen              
	 */
	SrpVerifierAndUser getSrpVerifierData(String authenticatedUser, String username, final int passwordIndex) throws ConfigurationTaskException;

	/**
	 * @param authenticatedUser Benutzer, der den Auftrag angestossen hat
	 * @param usernamePassword  Benutzer für den die Einmal-Passwörter gedacht sund
	 * @param passwords         Einmal-Passwörter
	 * @param append            Passwörter anhängen (falls nicht, bestehende Passwörter vorher löschen)
	 * @return Index des ersten angehängten Passworts
	 * @throws RequestException           Technischer Fehler, der Auftrag konnte nicht bearbeitet werden.
	 * @throws ConfigurationTaskException Die Konfiguration weigert sich den Auftrag auszuführen weil z.b. das Passwort falsch war, der Benutzer nicht die
	 *                                    nötigen Rechte besitzt usw..
	 */
	int setOneTimePasswords(String authenticatedUser, String usernamePassword, List<String> passwords, boolean append) throws ConfigurationTaskException, RequestException;

	/**
	 * Markiert eine Einmalpasswort als ungültig
	 * @param authenticatedUser Authentifizierter Benutzer
	 * @param usernamePassword Benutzer, dssen Passwort als ungültig markiert werden soll
	 * @param passwordIndex Index des Einmalpassworts
	 */
	void disableSingleServingPassword(String authenticatedUser, String usernamePassword, int passwordIndex) throws ConfigurationTaskException, RequestException;
}
