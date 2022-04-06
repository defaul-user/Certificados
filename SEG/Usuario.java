import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
/**
* Esta clase implementa el comportamiento de un usuario en una Infraestructura de Certificación
* @author Seg Red Ser
* @version 1.0
*/
public class Usuario {
	private GestionObjetosPEM pem;
	private RSAKeyParameters clavePrivada;
	private RSAKeyParameters clavePublica;
	/**
	 * Método que genera y devuelve las claves del usuario.
	 * @param fichClavePrivada: String con el nombre del fichero donde se guardará la clave privada en formato PEM
	 * @param fichClavePublica: String con el nombre del fichero donde se guardará la clave publica en formato PEM
     * @throws IOException 	
	 * @return AsymmetricCipherKeyPair: Par de claves del usuario.
	 */
	public AsymmetricCipherKeyPair generarClaves (String fichClavePrivada, String fichClavePublica) throws IOException{
		
		AsymmetricCipherKeyPair claves;

		// Esto es nuevo respecto de la P1. Se debe instanciar un objeto de la clase GestionClaves proporcionada
		GestionClaves gc = new GestionClaves (); 
		pem = new GestionObjetosPEM();
		
		// Asignar claves a los atributos correspondientes
		// Escribir las claves en un fichero en formatos estándar de clave privada y pública!!
		claves = gc.generarClaves(BigInteger.valueOf(3),2048);
		
		// FORMATO DER
		// Primero, generamos la calve en formato PrivateKeyInfo y despues con el getClavePrivadaMotor generamos un RSAKeyParameters
		clavePrivada = gc.getClavePrivadaMotor(gc.getClavePrivadaPKCS8(claves.getPrivate()));
		clavePublica = gc.getClavePublicaMotor(gc.getClavePublicaSPKI(claves.getPublic()));
		// REPRESENTACION EN FORMATO PEM
		pem.escribirObjetoPEM(pem.PKCS8KEY_PEM_HEADER, gc.getClavePrivadaPKCS8(clavePrivada).getEncoded(),fichClavePrivada);
		pem.escribirObjetoPEM(pem.PUBLICKEY_PEM_HEADER, gc.getClavePublicaSPKI(clavePublica).getEncoded(),fichClavePublica);
		
		return claves;
    }//end generarClaves

	/**
	 * Método que genera una petición de certificado en formato PEM,almacenando esta petición en un fichero.
	 * @param parClaves: AsymmetricCipherKeyPair
	 * @param fichPeticion: String con el nombre del fichero donde se guardará la petición de certificado
	 * @throws IOException 
	 * @throws OperatorCreationException 
	 */
	public void crearPetCertificado(AsymmetricCipherKeyPair parClaves,String fichPeticion ) throws OperatorCreationException, IOException {
		X500Name nombreEmisor = new X500Name ("C=ES, O=DTE, CN=Covid19"); // Instancia del nombre del propietario del certificado en formato X500
		GestionClaves gc = new GestionClaves (); 

		/* Constructor del Certificado en PKCS10, al cual le pasamos el nombre del propietario (emisor) en formato X500 y su calve publica en formato SubjectkeyInfo tal como indican en la API
		   --> https://www.bouncycastle.org/docs/pkixdocs1.5on/org/bouncycastle/pkcs/PKCS10CertificationRequestBuilder.html */
		PKCS10CertificationRequestBuilder constructorPeticion = new PKCS10CertificationRequestBuilder(nombreEmisor,gc.getClavePublicaSPKI(parClaves.getPublic()));
	   	// Configurar hash para resumen y algoritmo firma de la misma forma que lo hicimos con la CA
		DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder(); //Firma
		DefaultDigestAlgorithmIdentifierFinder digAlgFinder= new DefaultDigestAlgorithmIdentifierFinder();	//Resumen - Has
		
		AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA256withRSA"); // Algoritmo para la firma
		AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);
		BcContentSignerBuilder csBuilder = new BcRSAContentSignerBuilder(sigAlgId,digAlgId); // Constructor del contenido de la firma
		
		// Construimos la peticion del CERTIFICADO
		PKCS10CertificationRequest peticion = constructorPeticion.build(csBuilder.build(parClaves.getPrivate()));
		// La solicitud se firma con la clave privada del usuario y se escribe en fichPeticion en formato PEM
		pem =  new GestionObjetosPEM();
		pem.escribirObjetoPEM(pem.PKCS10_PEM_HEADER,peticion.getEncoded(),fichPeticion);
	}// end crearPetCertificado
	
	/**
	 * Método que verifica un certificado de una entidad.
	 * @param fichCertificadoCA: String con el nombre del fichero donde se encuentra el certificado de la CA
	 * @param fichCertificadoUsu: String con el nombre del fichero donde se encuentra el certificado de la entidad
     * @throws CertException 
	 * @throws OperatorCreationException 
	 * @throws IOException 
	 * @throws FileNotFoundException 	
	 * @return boolean: true si verificación OK, false en caso contrario.
	 */
    public boolean verificarCertificadoExterno(String fichCertificadoCA, String fichCertificadoUsu)throws OperatorCreationException, CertException, FileNotFoundException, IOException {
		pem =  new GestionObjetosPEM();
		GestionClaves gc = new GestionClaves (); 
		
		RSAKeyParameters CAKey;
		X509CertificateHolder certificado; // Objeto para el certificado X509
		boolean verificado = false;
	// Leemos el fichero que contiene el certificado del usuario y hacemos un cast de Object a X509CertificateHolder
		X509CertificateHolder certUsuario = (X509CertificateHolder)pem.leerObjetoPEM(fichCertificadoUsu);
		//--> https://www.bouncycastle.org/docs/pkixdocs1.5on/index.html
		Calendar fecha = Calendar.getInstance();
		fecha.setTime(new Date());
		if(certUsuario.getNotAfter().after(fecha.getTime())&&certUsuario.getNotBefore().before(fecha.getTime())){
		//Si la fecha es correcta y el certificado es valido entonces comprobamos la firma 
			//Leemos el certificado y extraemos la clave publica de la CA en formato RSAKeyParameters
			certificado = (X509CertificateHolder) pem.leerObjetoPEM(fichCertificadoCA); // Creamos el objeto certificado, con el certificado de la CA
			CAKey = gc.getClavePublicaMotor(certificado.getSubjectPublicKeyInfo()); // Del certificado de la CA, extraemos su clave publica
			// Verificamos la firma
			ContentVerifierProvider contentVerifierProvider = new BcRSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder()).build(CAKey);
			if(certUsuario.isSignatureValid(contentVerifierProvider)){
				verificado = true;
			}// end if 
		}// end if 
		return verificado;
	}	// end verificarCertificadoExterno
}//end Usuario