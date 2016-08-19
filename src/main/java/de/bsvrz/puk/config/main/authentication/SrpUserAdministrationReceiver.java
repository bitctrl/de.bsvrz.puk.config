/*
 * Copyright 2016 by Kappich Systemberatung Aachen
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

import de.bsvrz.dav.daf.communication.lowLevel.telegrams.SrpAnswer;
import de.bsvrz.dav.daf.communication.lowLevel.telegrams.SrpValidateAnswer;
import de.bsvrz.dav.daf.communication.lowLevel.telegrams.SrpValidateRequest;
import de.bsvrz.dav.daf.communication.srpAuthentication.*;
import de.bsvrz.dav.daf.main.config.ConfigurationTaskException;
import de.bsvrz.dav.daf.main.impl.config.request.RequestException;
import de.bsvrz.dav.daf.main.impl.config.request.UserAdministrationQuery;
import de.bsvrz.dav.daf.util.Throttler;
import de.bsvrz.sys.funclib.dataSerializer.NoSuchVersionException;
import de.bsvrz.sys.funclib.dataSerializer.Serializer;
import de.bsvrz.sys.funclib.dataSerializer.SerializingFactory;

import java.io.*;
import java.math.BigInteger;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Gegenstück zu {@link de.bsvrz.dav.daf.main.impl.config.request.SrpUserAdministration} auf Konfigurationsseite
 *
 * @author Kappich Systemberatung
 */
public class SrpUserAdministrationReceiver {

	/**
	 * Benutzerverwaltungs-Schnittstelle der Konfiguration
	 */
	private final Authentication _authentication;

	/**
	 * Serverseitige SRP-Implementierung
	 */
	private SrpServerAuthentication _srpServerAuthentication = null;

	/**
	 * Implementierung der Verschlüsselung
	 */
	private SrpTelegramEncryption _encryption = null;

	/**
	 * Name des authentifizierten Benutzers
	 */
	private String _authenticatedUser = null;

	/**
	 * Klasse zum Ausbremsen von Brute-Force-Angriffen
	 */
	private static final Throttler _throttle = new Throttler(Duration.ofSeconds(1), Duration.ofSeconds(5));

	/** 
	 * Erstellt ein neues SrpUserAdministrationReceiver-Objekt
	 * @param authentication Benutzerverwaltungs-Schnittstelle der Konfiguration
	 */
	public SrpUserAdministrationReceiver(final Authentication authentication) {
		_authentication = authentication;
	}

	/**
	 * Führt einen Auftrag aus
	 *
	 * @param resultSerializer In dieses Objekt wird das Ergebnis des Auftrags geschrieben
	 * @param encryptedData    Verschlüsselter Auftrag
	 * @throws ConfigurationTaskException
	 * @throws RequestException
	 */
	public void processTask(final Serializer resultSerializer, final byte[] encryptedData) throws ConfigurationTaskException, RequestException {
		try {
			if(_encryption == null){
				throw new IllegalStateException("Ungültige Telegrammabfolge, Authentifizierung fehlt");
			}
			byte[] decryptedData = _encryption.decrypt(encryptedData);
			// Format des Byte-Arrays:
			// - String - Enum-Wert des Auftrags
			// - byte[] - Auftrags-Spezifische Bytes, siehe Enum-Definition
			try(DataInputStream dataInputStream = new DataInputStream(new ByteArrayInputStream(decryptedData))) {
				String task = dataInputStream.readUTF();
				try {
					UserAdministrationQuery query = UserAdministrationQuery.valueOf(task);
					ByteArrayOutputStream out = new ByteArrayOutputStream();
					processQuery(query, dataInputStream, new DataOutputStream(out));
					// Antwort verschlüsseln
					resultSerializer.writeBytes(_encryption.encrypt(out.toByteArray()));
				}
				catch(IllegalArgumentException e) {
					throw new ConfigurationTaskException("Unbekannte Benutzerverwaltungs-Anfrage: " + task + ". Vielleicht sollte die Konfiguration aktualisiert werden?", e);
				}
			}
		}
		catch(IOException e) {
			throw new ConfigurationTaskException(e);
		}
	}

	private void processQuery(final UserAdministrationQuery query, final DataInputStream in, final DataOutputStream out) throws IOException, ConfigurationTaskException, RequestException {
		switch(query){
			case IsUserValid:
				out.writeByte(_authentication.isUser(in.readUTF()) ? 1 : 0);
				break;
			case IsUserAdmin:
				out.writeByte(_authentication.isUserAdmin(_authenticatedUser, in.readUTF()) ? 1 : 0);
				break;
			case ClearSingleServingPasswords:
				_authentication.clearSingleServingPasswords(_authenticatedUser, in.readUTF());
				break;
			case DeleteUser:
				_authentication.deleteUser(_authenticatedUser, in.readUTF());
				break;
			case GetOneTimePasswordCount:
				out.writeInt(_authentication.countRemainingSingleServingPasswords(_authenticatedUser, in.readUTF()));
				break;	
			case GetOneTimePasswordIDs:
				int[] passwordIDs = _authentication.getRemainingSingleServingPasswordIDs(_authenticatedUser, in.readUTF());
				out.writeInt(passwordIDs.length);
				for(int passwordID : passwordIDs) {
					out.writeInt(passwordID);
				}
				break;
			case ChangeUserPassword:
				_authentication.changeUserPassword(_authenticatedUser, in.readUTF(), in.readUTF());
				break;
			case DisableOneTimePassword:
				_authentication.disableSingleServingPassword(_authenticatedUser, in.readUTF(), in.readInt());
				break;
			case SetOneTimePasswords:
				String user = in.readUTF();
				boolean append = in.readBoolean();
				int passwordCount = in.readInt();
				final List<String> passwords = new ArrayList<String>(passwordCount);
				for(int i = 0; i < passwordCount; i++){
				    passwords.add(in.readUTF());
				}
				out.writeInt(_authentication.setOneTimePasswords(_authenticatedUser, user, passwords, append));
				break;
			case GetSrpVerifier:
				SrpVerifierAndUser verifierData = _authentication.getSrpVerifierData(_authenticatedUser, in.readUTF(), in.readInt());
				out.writeLong(verifierData.getUserLogin().toLong());
				out.writeUTF(verifierData.getVerifier().toString());
				out.writeBoolean(verifierData.isPlainTextPassword());
				break;
			case CreateNewUser:
				try {
					_authentication.createNewUser(_authenticatedUser, SerializingFactory.createDeserializer(2, in));
				}
				catch(NoSuchVersionException e) {
					throw new IOException(e);
				}
				break;
			case ChangeUserRights:
				_authentication.changeUserRights(_authenticatedUser, in.readUTF(), in.readBoolean());
				break;
			default:
				throw new AssertionError("Unbekannte Anfrage: " + query);
		}
	}

	public void processSrpRequest(final Serializer resultSerializer, final String userName) throws ConfigurationTaskException  {
		// Benutzerverwaltung dard nicht mit Einmalpassworten benutzt werden, daher -1
		SrpVerifierAndUser data = _authentication.getSrpVerifierData(userName, userName, -1);
		
		SrpCryptoParameter srpCryptoParameter = data.getVerifier().getSrpCryptoParameter();
		
		_srpServerAuthentication = new SrpServerAuthentication(srpCryptoParameter);
		try {
			BigInteger b;
			b = _srpServerAuthentication.step1(userName, data.getVerifier().getSalt(), data.getVerifier().getVerifier(), !data.getUserLogin().isAuthenticated());
			SrpAnswer srpAnswer = new SrpAnswer(b, data.getVerifier().getSalt(), srpCryptoParameter);
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			srpAnswer.write(new DataOutputStream(out));
			resultSerializer.writeBytes(out.toByteArray());
		}
		catch(IOException e) {
			throw new ConfigurationTaskException(e);
		}
	}

	public void processValidateRequest(final Serializer resultSerializer, final byte[] srpValidateRequest) throws ConfigurationTaskException  {
		try {
			if(_srpServerAuthentication == null){
				throw new IllegalStateException("Ungültige Telegrammabfolge, SrpRequest fehlt");
			}
			SrpValidateRequest srpRequestTelegram = new SrpValidateRequest();
			srpRequestTelegram.read(new DataInputStream(new ByteArrayInputStream(srpValidateRequest)));
			BigInteger m2 = _srpServerAuthentication.step2(srpRequestTelegram.getA(), srpRequestTelegram.getM1());
			
			// Passwort ist korrekt
			_throttle.trigger(false);
			
			_authenticatedUser = _srpServerAuthentication.getAuthenticatedUser();
			_encryption = new SrpTelegramEncryption(SrpUtilities.bigIntegerToBytes(_srpServerAuthentication.getSessionKey()), false, _srpServerAuthentication.getSrpCryptoParams());
			SrpValidateAnswer srpAnswer = new SrpValidateAnswer(m2);
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			srpAnswer.write(new DataOutputStream(out));
			resultSerializer.writeBytes(out.toByteArray());
		}
		catch(Exception e) {
			// vermutlich Passwort falsch oder anderer Fehler
			_throttle.trigger(true);
			throw new ConfigurationTaskException(e.getMessage(), e);
		}
	}
}
