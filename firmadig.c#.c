{\rtf1\ansi\ansicpg1252\cocoartf2868
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;}
{\*\expandedcolortbl;;}
\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0

\f0\fs24 \cf0 // ============================================================\
// Escenario 2: Firma Digital RSA-4096 + SHA-384 de Reportes\
// Namespace: System.Security.Cryptography\
// ============================================================\
\
using System;\
using System.IO;\
using System.Security.Cryptography;\
using System.Text;\
using Amazon.KeyManagementService;  // AWSSDK.KeyManagementService\
using Amazon.KeyManagementService.Model;\
\
namespace FinancialReportSigning\
\{\
    public class ReportSigner\
    \{\
        // RSA-4096 \'97 clave privada almacenada en AWS CloudHSM\
        // (en producci\'f3n se accede v\'eda PKCS#11 al HSM; aqu\'ed se simula)\
\
        private readonly RSA _rsaPrivateKey;\
        private readonly RSA _rsaPublicKey;\
\
        public ReportSigner()\
        \{\
            // Generar par de claves RSA-4096\
            // En producci\'f3n: cargar desde CloudHSM v\'eda PKCS#11\
\
            _rsaPrivateKey = RSA.Create(4096);\
\
            // Exportar solo la parte p\'fablica para el verificador\
            _rsaPublicKey = RSA.Create();\
\
            _rsaPublicKey.ImportRSAPublicKey(\
                _rsaPrivateKey.ExportRSAPublicKey(),\
                out _\
            );\
        \}\
\
        /// <summary>\
        /// Firma un reporte PDF calculando su digest SHA-384\
        /// y cifrando el digest con RSA-4096.\
        /// </summary>\
        public SignedReport SignReport(byte[] reportPdfBytes)\
        \{\
            // =================================================\
            // Paso 1: Calcular SHA-384 del documento\
            // =================================================\
\
            byte[] digest;\
\
            using (var sha384 = SHA384.Create())\
            \{\
                digest = sha384.ComputeHash(reportPdfBytes);\
            \}\
\
            // =================================================\
            // Paso 2: Firmar digest con RSA-4096\
            // =================================================\
\
            byte[] signature = _rsaPrivateKey.SignHash(\
                digest,\
                HashAlgorithmName.SHA384,\
                RSASignaturePadding.Pkcs1\
            );\
\
            Console.WriteLine(\
                $"Digest SHA-384: \{Convert.ToHexString(digest)\}"\
            );\
\
            Console.WriteLine(\
                $"Firma (bytes): \{signature.Length\} bytes (RSA-4096)"\
            );\
\
            return new SignedReport\
            \{\
                ReportBytes = reportPdfBytes,\
                DigestSHA384 = digest,\
                DigitalSignature = signature,\
                SignatureAlgorithm =\
                    "RSA-4096 + SHA-384 (PKCS#1 v1.5)"\
            \};\
        \}\
\
        /// <summary>\
        /// Verifica la firma digital del reporte.\
        /// </summary>\
        public bool VerifyReport(SignedReport signedReport)\
        \{\
            // =================================================\
            // Paso 1: Recalcular digest SHA-384\
            // =================================================\
\
            byte[] localDigest;\
\
            using (var sha384 = SHA384.Create())\
            \{\
                localDigest =\
                    sha384.ComputeHash(signedReport.ReportBytes);\
            \}\
\
            // =================================================\
            // Paso 2: Verificar firma con clave p\'fablica\
            // =================================================\
\
            bool isValid = _rsaPublicKey.VerifyHash(\
                localDigest,\
                signedReport.DigitalSignature,\
                HashAlgorithmName.SHA384,\
                RSASignaturePadding.Pkcs1\
            );\
\
            // =================================================\
            // Paso 3: Comparaci\'f3n constante de digest\
            // =================================================\
\
            bool digestMatch =\
                CryptographicOperations.FixedTimeEquals(\
                    localDigest,\
                    signedReport.DigestSHA384\
                );\
\
            return isValid && digestMatch;\
        \}\
    \}\
\
    // =========================================================\
    // MODELO DE REPORTE FIRMADO\
    // =========================================================\
\
    public class SignedReport\
    \{\
        public byte[] ReportBytes \{ get; set; \}\
\
        public byte[] DigestSHA384 \{ get; set; \}\
\
        public byte[] DigitalSignature \{ get; set; \}\
\
        public string SignatureAlgorithm \{ get; set; \}\
    \}\
\
    // =========================================================\
    // PROGRAMA DEMO\
    // =========================================================\
\
    class Program\
    \{\
        static void Main(string[] args)\
        \{\
            var signer = new ReportSigner();\
\
            // Simular PDF financiero\
            byte[] reportBytes = Encoding.UTF8.GetBytes(\
                "REPORTE FINANCIERO JULIO 2025 \'97 " +\
                "Total activos: $12,450,000 MXN"\
            );\
\
            // =================================================\
            // FIRMA\
            // =================================================\
\
            Console.WriteLine(\
                "=== FIRMA DEL REPORTE ==="\
            );\
\
            var signedReport =\
                signer.SignReport(reportBytes);\
\
            // =================================================\
            // VERIFICACI\'d3N\
            // =================================================\
\
            Console.WriteLine(\
                "\\n=== VERIFICACI\'d3N POR REGULADOR ==="\
            );\
\
            bool valid =\
                signer.VerifyReport(signedReport);\
\
            Console.WriteLine(\
                $"Firma v\'e1lida: \{valid\}"\
            );\
\
            // =================================================\
            // DETECCI\'d3N DE MANIPULACI\'d3N\
            // =================================================\
\
            Console.WriteLine(\
                "\\n=== DETECCI\'d3N DE MANIPULACI\'d3N ==="\
            );\
\
            var tampered = new SignedReport\
            \{\
                ReportBytes = Encoding.UTF8.GetBytes(\
                    "REPORTE FINANCIERO JULIO 2025 \'97 " +\
                    "Total activos: $99,999,999 MXN"\
                ),\
\
                DigestSHA384 =\
                    signedReport.DigestSHA384,\
\
                DigitalSignature =\
                    signedReport.DigitalSignature,\
\
                SignatureAlgorithm =\
                    signedReport.SignatureAlgorithm\
            \};\
\
            bool tamperedValid =\
                signer.VerifyReport(tampered);\
\
            Console.WriteLine(\
                $"Reporte manipulado v\'e1lido: \{tamperedValid\}"\
            );\
\
            Console.WriteLine(\
                "\uc0\u10003  Manipulaci\'f3n detectada correctamente"\
            );\
        \}\
    \}\
\}\
}