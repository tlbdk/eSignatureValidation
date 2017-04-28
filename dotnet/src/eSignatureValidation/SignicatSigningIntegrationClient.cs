using System;
using System.CodeDom;
using System.Collections.Generic;
using System.Data.Entity;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using MobileLife.OBCO.Data.Entity;
using MobileLife.OBCO.Data.SignicatDocumentServiceReference;
using MobileLife.OBCO.Data.SignicatPackagingServiceReference;
using MobileLife.SimpleWebApi.Extension;
using MobileLife.SimpleWebApi.Logging;
using Newtonsoft.Json;

namespace MobileLife.OBCO.Data
{
    // https://preprod.signicat.com/ws/documentservice-v2?wsdl ,  https://preprod.signicat.com/ws/packagingservice-v4?wsdl

    public class SignicatSigningIntegrationClient
    {
        private readonly DatabaseContext _db;
        private readonly HttpClient _httpClient;
        private readonly string _userUrl;
        private readonly string _sdsUrl;
        private readonly string _username;
        private readonly string _profile = "default";
        private readonly string _password;
        private readonly bool _testing;
        private readonly ILog _log;
        private readonly DocumentEndPointClient _documentClient;
        private readonly PackagingEndPointClient _packagingClient;
        
        public SignicatSigningIntegrationClient(DatabaseContext databaseContext, string userUrl, string sdsUrl, string documentServiceUrl, string packagingServiceUrl, string username, string password, bool testing = false, X509Certificate2 clientCertificate = null)
        {
            _log = LogManager.GetLogger(GetType());
            _log.Debug(".ctor");
            _db = databaseContext;
            _sdsUrl = sdsUrl;
            _username = username;
            _password = password;
            _testing = testing;
            _userUrl = userUrl;

            var httpClientHandler = new WebRequestHandler
            {
                Credentials = new NetworkCredential(_username, _password),
                UseProxy = true,
                PreAuthenticate = true,
            };
           
            var signicatBinding = new BasicHttpBinding
            {
                Security =
                {
                    Mode = BasicHttpSecurityMode.Transport,
                },
                UseDefaultWebProxy = true
            };

            _documentClient = new DocumentEndPointClient(signicatBinding, new EndpointAddress(documentServiceUrl));
            _packagingClient = new PackagingEndPointClient(signicatBinding, new EndpointAddress(packagingServiceUrl));

            if (clientCertificate != null)
            {
                httpClientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
                httpClientHandler.ClientCertificates.Add(clientCertificate);

                 signicatBinding.Security.Transport.ClientCredentialType = HttpClientCredentialType.Certificate;
                _documentClient.ClientCredentials.ClientCertificate.Certificate = clientCertificate;
                _packagingClient.ClientCredentials.ClientCertificate.Certificate = clientCertificate;
            }

             _httpClient = new HttpClient(httpClientHandler) {Timeout = TimeSpan.FromSeconds(30)};

            _log.DebugFormat("Initialized with settings: username : {0} password : {1} testing : {2} userUrl : {3}",
                _username, _password, _testing.ToHumanReadableBool(), _userUrl);
        }

        public async Task<string> StartDocumentSigning(string nationalId, string documentTitle, byte[] documentBytes, int documentId, string successUrl, string cancelUrl)
        {
            _log.Info("Start document siging ");
            _log.DebugFormat("Called with: nationalId : {0}, successUrl : {1} cancelUrl : {2}", nationalId, successUrl, cancelUrl);

            var stopwatch = new Stopwatch();
            stopwatch.Reset();
            stopwatch.Start();
            var sdsDocumentId = await UploadDocument(documentBytes);
            stopwatch.Stop();
            _log.Debug("Upload, Ticks: " + stopwatch.ElapsedTicks + " mS: " + stopwatch.ElapsedMilliseconds);

            // Generate random task id
            var taskId = Convert.ToBase64String(Guid.NewGuid().ToByteArray()).Replace("=", "").Replace("+", "").Replace("/", "");
            successUrl += $"?task_id={taskId}";
            cancelUrl += $"?task_id={taskId}";
         
            stopwatch.Reset();
            stopwatch.Start();
            var requestId = await CreateDocumentSigningRequest(sdsDocumentId, documentTitle, taskId, nationalId, successUrl, cancelUrl);
            stopwatch.Stop();
            _log.Debug("Create, Ticks: " + stopwatch.ElapsedTicks + " mS: " + stopwatch.ElapsedMilliseconds);

            // Make sure we reset the signature record
            var signature =_db.DocumentSignatures.SingleOrDefault(s => s.DocumentId == documentId) ?? _db.DocumentSignatures.Add(new DbDocumentSignature());
            signature.NationalId = nationalId;
            signature.StartedDate = DateTimeOffset.Now;
            signature.RequestId = requestId;
            signature.DocumentId = documentId;
            signature.DocumentSdsId = sdsDocumentId;
            signature.TaskId = taskId;
            await _db.SaveChangesAsync();
            
            var returnUrl = _userUrl + $"?request_id={requestId}&task_id={taskId}";
            _log.InfoFormat("user url: {0}", returnUrl);

            return returnUrl;
        }

        public async Task<int> FinishDocumentSigning(string nationalId, string taskId)
        {
            _log.InfoFormat("Finish document signing for cpr: {0}", nationalId.MaskLastChars(4));
            _log.DebugFormat("Customer id : {0} and taskId : {1}", nationalId, taskId);

            // Get request id from DB
            var signature = await _db.DocumentSignatures.SingleOrDefaultAsync(x => x.TaskId == taskId & x.NationalId == nationalId);
            if (signature == null)
            {
                _log.ErrorFormat("Unable to locate taskId {0} for customer", taskId);
                throw new SignicatSigningIntegrationException("Could not find taskId for this customer");
            }

            if (signature.Sdo != null)
            {
                _log.Info("Signature has already been saved");
                // Signature already saved
                return signature.Id;
            }

            try
            {
                var ltvSdoXml = await GetSignedDigitalObject(signature.RequestId);
                if (ltvSdoXml == null)
                {
                    _log.Error("Unable to fetch SDO from Signicat");
                    throw new SignicatSigningIntegrationException("Failed to fetch sdo from Signicat");
                }

                // Save SDO's to database
                signature.Sdo = Encoding.UTF8.GetBytes(ltvSdoXml);
                signature.SavedDate = DateTimeOffset.Now;

                var documentBytes = await _db.Documents.Where(d => d.Id == signature.DocumentId).Select(d => d.Document).SingleAsync();
                signature.SignedDate = signature.ValidateSignature(documentBytes, _testing);

                _log.Info("Saving signature to database");
                await _db.SaveChangesAsync();
            }
            finally
            {
                // Cleanup all documents uploaded to Signicat
                await DeleteDocumentSigningRequest(signature.RequestId);
                if (signature.DocumentSdsId != null)
                {
                    await DeleteDocument(_sdsUrl + signature.DocumentSdsId);
                }
            }

            return signature.Id;
        }

        public async Task<bool> DeleteDocument(string url)
        {
            _log.Info("Delete document");
            var response = await _httpClient.DeleteAsync(url);
            _log.InfoFormat("Delete completed, all ok? {0}", response.IsSuccessStatusCode.ToHumanReadableBool());
            return response.IsSuccessStatusCode;
        }

        public async Task<string> UploadDocument(byte[] bytes)
        {
            _log.Info("Uploading document to remote server");
            using (var documentStream = new MemoryStream(bytes))
            {
                try
                {
                    HttpContent content = new StreamContent(documentStream);
                    content.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");
                    var response = await _httpClient.PostAsync(_sdsUrl, content);
                    if (response.IsSuccessStatusCode)
                    {
                        var documentId = await response.Content.ReadAsStringAsync();
                        _log.InfoFormat("Upload successful, documentId is: '{0}'", documentId);
                        return documentId;
                    }
                    else
                    {
                        var errorContent = await response.Content.ReadAsStringAsync();
                        _log.ErrorFormat("Upload failed with errorcode: {0}", response.StatusCode);
                        throw new SignicatSigningIntegrationException("Document upload failed with error code " + response.StatusCode);
                    }
                }
                catch (TaskCanceledException)
                {
                    _log.Error("Timeout while waiting for upload to finish");
                    throw new SignicatSigningIntegrationException("Timed out waiting for upload to finish");
                }
                catch (Exception ex)
                {
                    _log.Error("Bad stuff", ex);
                    throw ex;
                }
            }
        }

        public async Task<string> CreateDocumentSigningRequest(string sdsDocumentId, string documentDescription, string taskId, string ssn, string successUrl, string cancelUrl, string callbackUrl = null)
        {
            var docId = Convert.ToBase64String(Guid.NewGuid().ToByteArray()).Replace("=", "").Replace("+", "").Replace("/", "");
            var subjectId = Convert.ToBase64String(Guid.NewGuid().ToByteArray()).Replace("=", "").Replace("+", "").Replace("/", "");
            var clientReference = Convert.ToBase64String(Guid.NewGuid().ToByteArray()).Replace("=", "").Replace("+", "").Replace("/", "");

            var request = new createrequestrequest
            {
                service = _username,
                password = _password,
                request = new[]
                {
                    new request
                    {
                        clientreference = clientReference, 
                        language = "da",
                        profile = _profile,
                        document = new document[]
                        {
                            new sdsdocument()
                            {
                                id = docId,
                                refsdsid = sdsDocumentId,
                                description = documentDescription,
                            },
                        },
                        task = new[]
                        {
                            new task
                            {
                                id = taskId,
                                bundleSpecified = true,
                                bundle = false,
                                documentaction = new[]
                                {
                                     new documentaction
                                     {
                                         type = documentactiontype.sign,
                                         documentref = docId
                                     }
                                    
                                },
                                signature = new[]
                                {
                                    new signature
                                    {
                                        method = new[]
                                        {
                                            "nemid-sign"
                                        }
                                    }
                                },
                                ontaskcancel = cancelUrl,
                                ontaskcomplete = successUrl

                            }
                        },
                    }
                }
            };

            if (ssn != null)
            {
                request.request[0].subject = new[]
                {
                    new subject
                    {
                        id = subjectId,
                        nationalid = ssn
                    }
                };
                request.request[0].task[0].subjectref = subjectId;
            }

            if (callbackUrl != null)
            {
                request.request[0].notification = new notification[]
                {
                    new notification
                    {
                        notificationid = "req_not_1", // LTDO: set this to something that makes sense
                        message = "Wealth_sign_1",
                        recipient = callbackUrl,
                        type = notificationtype.URL,
                    }
                };

                request.request[0].task[0].notification = new[]
                {
                    new notification()
                    {
                        notificationid = "req0_task0_1",
                        recipient = callbackUrl + "task/",
                        message = "Wealth_sign_task_1",
                        type = notificationtype.URL,
                        schedule = new schedule[]
                        {
                            new schedule
                            {
                                stateis = taskstatus.created
                            }
                        }
                    }
                };
            }

            var response = await _documentClient.createRequestAsync(request);
            return response.createrequestresponse.requestid[0];
        }

        public async Task<string> GetSignedDigitalObjectUrl(string requestId)
        {
            var request = new getstatusrequest
            {
                service = _username,
                password = _password,
                requestid = new[]
                {
                    requestId
                }
            };

            var taskStatusInfo = await _documentClient.getStatusAsync(request);
            if (taskStatusInfo.getstatusresponse1[0].taskstatus == taskstatus.completed)
            {
                var sdoUrl = taskStatusInfo.getstatusresponse1[0].documentstatus[0].resulturi;
                return sdoUrl;
            }
            else
            {
                return null;
            }
            
        }

        public async Task<bool> DeleteDocumentSigningRequest(string requestId)
        {
            _log.InfoFormat("Delete document signing request for requestId: {0}", requestId);

            var request = new deleterequestrequest()
            {
                service = _username,
                password = _password,
                requestid = new[]
                {
                    requestId
                }
            };

            var taskStatusInfo = await _documentClient.deleteRequestAsync(request);
            if (taskStatusInfo.deleterequestresponse.deleted == 1)
            {
                return true;
            }
            else
            {
                return false;
            }
            
        }

        public async Task<string> GetSignedDigitalObject(string requestId)
        {
            _log.InfoFormat("Get signed digital object for requestId: {0}", requestId);

            var sdoUrl = await GetSignedDigitalObjectUrl(requestId);
            return await _httpClient.GetStringAsync(sdoUrl);
        } 

        public async Task<string> GetPadEsSignedPdfUrl(string requestId)
        {
            var sdoUrl = await GetSignedDigitalObjectUrl(requestId);
            var request = new createpackagerequest
            {
                service = _username,
                password = _password,
                version = "4",
                packagingmethod = "pades",
                validationpolicy = "ltvsdo-validator",
                Items = new object[]
                {
                    new documentid
                    {
                        uridocumentid = sdoUrl
                    }
                },
                sendresulttoarchive = false
            };

            var createPackageResponse = _packagingClient.createpackage(request);
            var padesDocumentId = createPackageResponse.id;
            var padEsSignedPdfUrl = _sdsUrl + padesDocumentId;
            return padEsSignedPdfUrl;
        }
    }

    [Serializable]
    public class SignicatSigningIntegrationException : Exception
    {
        public SignicatSigningIntegrationException() { }
        public SignicatSigningIntegrationException(string message) : base(message) { }
        public SignicatSigningIntegrationException(string message, Exception inner) : base(message, inner) { }
    }
}