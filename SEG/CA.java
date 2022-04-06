import java.util.Calendar;
import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;

import java.util.Date;

import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;

/**
* Esta clase implementa el comportamiento de una CA
* @author Seg Red Ser
* @version 1.0
*/
public class CA {
	//Declaracion de objetos para los distintos atributos del certificado
	private final X500Name nombreEmisor;
	private BigInteger numSerie;
	private final int añosValidez; 
	//Constantes para el nombre de los ficheros
	public final static String NOMBRE_FICHERO_CRT = "CertificadoCA.crt";
	public final static String NOMBRE_FICHERO_CLAVES = "CA-clave";
	
	private RSAKeyParameters clavePrivadaCA;
	private RSAKeyParameters clavePublicaCA;
	private GestionClaves gc; // Clase ya codificada que nos ayuda a gestionar las claves, en sus diferentes formatos
	private GestionObjetosPEM pem; // Clase ya codificada que nos ayuda a la hora de gestionar los ficheros en los distintos formatos. Tanto en la lectura como en la escritura
	private X509CertificateHolder certificado; // Objeto para el certificado X509
	private Calendar fecha;

	
	/**
	 * Constructor de la CA. 
	 * Inicializa atributos de la CA a valores por defecto
	 */
	public CA () {
		// Distinguished Name DN. C Country, O Organization name, CN Common Name. 
		this.nombreEmisor = new X500Name ("C=ES, O=DTE, CN=CA");
		this.numSerie = BigInteger.valueOf(1);
		this.añosValidez = 4; // Son los años de validez del certificado de usuario, para la CA el valor es 4
	}//end constructor CA 
	
	 /**
	 * Método que inicializa la CA. Carga la parejas de claves de la CA o genera la parejas de claves de la CA y el certificado 
         * autofirmado de la CA.
	 * @param cargar:boolean. Si es true, carga las claves de ficheros existentes. Si es false, genera datos nuevos y los guarda en 
         * ficheros para su uso posterior. 
	 * @throws OperatorCreationException
	 * @throws IOException 
	 */
	public void inicializar (boolean cargar) throws OperatorCreationException, IOException{
		
		gc = new GestionClaves (); // Clase ya codificada que nos ayuda a gestionar las claves, en sus diferentes formatos
		pem =  new GestionObjetosPEM(); // Clase ya codificada que nos ayuda a la hora de gestionar los ficheros en los distintos formatos. Tanto en la lectura como en la escritura
		if (cargar) {
			/* En el caso de que las claves ya hayan sido generadas, y con el fin de no tener que generar una pareja de claves nueva
			 * cada vez que el usuario decida actuar como CA, se cargaran las claves correspondientes de los ficheros que ya fueron generados con anterioridad.
			 * Asi pues, cargamos del fichero NOMBRE_FICHERO_CLAVES la calve privada y del fichero NOMBRE_FICHERO_CRT la clave publica de la CA */
			
			// Cogemos el fichero con el certificado y extraemos de el, la clave publica de "subject" que es la de la CA y despues con pem y gc la convertimos en un RSAKeyParameter
			certificado = (X509CertificateHolder) pem.leerObjetoPEM(NOMBRE_FICHERO_CRT);
			
			clavePublicaCA = gc.getClavePublicaMotor((SubjectPublicKeyInfo)pem.leerObjetoPEM(NOMBRE_FICHERO_CLAVES+"-publ.txt"));
			clavePrivadaCA = gc.getClavePrivadaMotor((PrivateKeyInfo)pem.leerObjetoPEM(NOMBRE_FICHERO_CLAVES+"-priv.txt"));

		} // end if
		else {
			/* En el cado de que sea la primera vez que el usuario entra como CA, se deben de generar una pareja de claves y 
			 * guardar la clave privada de la CA en el fichero indicado por NOMBRE_FICHERO_CLAVES y la publica en la misma variable "clavePublicaCA
			 * ya que cuando generemos el certificado, se incluira dentro del mismo, por lo que no es necesario almacenarla */
			fecha = Calendar.getInstance();
			fecha.setTime(new Date());
			fecha.add(Calendar.YEAR,añosValidez);
			AsymmetricCipherKeyPair claves;

			pem = new GestionObjetosPEM();

			claves = gc.generarClaves(BigInteger.valueOf(3),2048);
			// FORMATO DER
						// Primero, generamos la calve en formato PrivateKeyInfo y despues con el getClavePrivadaMotor generamos un RSAKeyParameters
			clavePrivadaCA = gc.getClavePrivadaMotor(gc.getClavePrivadaPKCS8(claves.getPrivate()));
			clavePublicaCA = gc.getClavePublicaMotor(gc.getClavePublicaSPKI(claves.getPublic()));
			// REPRESENTACION EN FORMATO PEM de la clave privada de la CA
			pem.escribirObjetoPEM(pem.PKCS8KEY_PEM_HEADER, gc.getClavePrivadaPKCS8(clavePrivadaCA).getEncoded(),NOMBRE_FICHERO_CLAVES+"-priv.txt");		
			pem.escribirObjetoPEM(pem.PUBLICKEY_PEM_HEADER, gc.getClavePublicaSPKI(clavePublicaCA).getEncoded(),NOMBRE_FICHERO_CLAVES+"-publ.txt");			
			// Generar un certificado autofirmado: 
			// 	1. Configurar parámetros para el certificado
			X509v3CertificateBuilder certBldr = new X509v3CertificateBuilder(nombreEmisor,numSerie,new Date(),fecha.getTime(),nombreEmisor,
																				gc.getClavePublicaSPKI(clavePublicaCA));
			// 	2. Configurar hash para resumen y algoritmo firma (MIRAR TRANSPARENCIAS DE APOYO EN MOODLE)
			DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder(); //Firma
			DefaultDigestAlgorithmIdentifierFinder digAlgFinder= new DefaultDigestAlgorithmIdentifierFinder();	//Resumen
			
			AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA256withRSA"); // Algoritmo para la firma
			AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);
			BcContentSignerBuilder csBuilder = new BcRSAContentSignerBuilder(sigAlgId,digAlgId);
			//	3. Generar certificado
			certificado = certBldr.build(csBuilder.build(clavePrivadaCA));
			//	4. Guardar el certificado en formato PEM como un fichero con extensión crt (NOMBRE_FICHERO_CRT)
			pem.escribirObjetoPEM(pem.CERTIFICATE_PEM_HEADER,certificado.getEncoded(), NOMBRE_FICHERO_CRT);
		} // end else		
	} // end inicializar
	
	/**
	 * Método que genera el certificado de un usuario a partir de una petición de certificación
	 * @param ficheroPeticion:String. Parámetro con la petición de certificación
	 * @param ficheroCertUsu:String. Parámetro con el nombre del fichero en el que se guardará el certificado del usuario
	 * @throws IOException 
	 * @throws PKCSException 
	 * @throws OperatorCreationException
	 * @throws CertException 
	 */
	public boolean certificarPeticion(String ficheroPeticion, String ficheroCertUsu) throws IOException, 
										OperatorCreationException, PKCSException, CertException{
		
		gc = new GestionClaves (); 
		pem =  new GestionObjetosPEM();
		
		RSAKeyParameters KpSujeto; // Clave publica del sujeto al que se le va a emitir el certificado 
		boolean ok = true;
		
		if(clavePublicaCA!=null && clavePrivadaCA!=null){ // Comprobamos que las claves de la CA han sido cargadas 			
		PKCS10CertificationRequest peticionUsu = (PKCS10CertificationRequest) pem.leerObjetoPEM(ficheroPeticion); // Leemos del fichero correspondiente, la peticion de certificacion del usuario
		KpSujeto = gc.getClavePublicaMotor(peticionUsu.getSubjectPublicKeyInfo()); // De la peticion, extraemos la clave publica del sujeto que quiere que se la certifiquemos
		// Verificamos la firma 
		ContentVerifierProvider contentVerifierProvider = new BcRSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder()).build(KpSujeto);
		if(peticionUsu.isSignatureValid(contentVerifierProvider)){ // Si la firma es verificada correctamente entonces ... 
			fecha = Calendar.getInstance();
			fecha.setTime(new Date());
			fecha.add(Calendar.YEAR,añosValidez);
			X509v3CertificateBuilder certBldr = new X509v3CertificateBuilder(nombreEmisor,numSerie,new Date(),fecha.getTime(),peticionUsu.getSubject(),
																				peticionUsu.getSubjectPublicKeyInfo()); // Contenedor del certificado que como CA vamos a emitirle al Sujeto 
			// 	2. Configurar hash para resumen y algoritmo firma (MIRAR TRANSPARENCIAS DE APOYO EN MOODLE)
			DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder(); //Firma
			DefaultDigestAlgorithmIdentifierFinder digAlgFinder= new DefaultDigestAlgorithmIdentifierFinder();	//Resumen
			
			AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA256withRSA"); // Algoritmo para la firma
			AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);
			BcContentSignerBuilder csBuilder = new BcRSAContentSignerBuilder(sigAlgId,digAlgId);
			//	3. Generar certificado
			certificado = certBldr.build(csBuilder.build(clavePrivadaCA));
			//	4. Guardar el certificado en formato PEM como un fichero con extensión crt (NOMBRE_FICHERO_CRT)
			pem.escribirObjetoPEM(pem.CERTIFICATE_PEM_HEADER,certificado.getEncoded(),ficheroCertUsu);
		}// end if 
		}else{
			ok = false; // Se ha producido un error
		}// end else
	return ok;
	}// end certificarPeticion
}// end CA