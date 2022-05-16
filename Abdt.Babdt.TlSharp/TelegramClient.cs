using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Abdt.Babdt.TlSharp.Auth;
using Abdt.Babdt.TlSharp.Network;
using Abdt.Babdt.TlSharp.Utils;
using Abdt.Babdt.TlShema;
using Abdt.Babdt.TlShema.Account;
using Abdt.Babdt.TlShema.Auth;
using Abdt.Babdt.TlShema.Contacts;
using Abdt.Babdt.TlShema.Help;
using Abdt.Babdt.TlShema.Messages;
using Abdt.Babdt.TlShema.Upload;

namespace Abdt.Babdt.TlSharp
{
    public class TelegramClient : IDisposable
    {
        private MtProtoSender _sender;
        private TcpTransport _transport;
        private string _apiHash = "";
        private int _apiId;
        private Session _session;
        private List<TLDcOption> dcOptions;
        private TcpClientConnectionHandler _handler;

        public TelegramClient(
          int apiId,
          string apiHash,
          ISessionStore store = null,
          string sessionUserId = "session",
          TcpClientConnectionHandler handler = null)
        {
            if (apiId == 0)
                throw new MissingApiConfigurationException("API_ID");
            if (string.IsNullOrEmpty(apiHash))
                throw new MissingApiConfigurationException("API_HASH");
            if (store == null)
                store = (ISessionStore)new FileSessionStore();
            this._apiHash = apiHash;
            this._apiId = apiId;
            this._handler = handler;
            this._session = Session.TryLoadOrCreateNew(store, sessionUserId);
            this._transport = new TcpTransport(this._session.DataCenter.Address, this._session.DataCenter.Port, this._handler);
        }

        public async Task ConnectAsync(bool reconnect = false)
        {
            if (this._session.AuthKey == null | reconnect)
            {
                Step3_Response step3Response = await Authenticator.DoAuthentication(this._transport);
                this._session.AuthKey = step3Response.AuthKey;
                this._session.TimeOffset = step3Response.TimeOffset;
            }
            this._sender = new MtProtoSender(this._transport, this._session);
            TLRequestGetConfig requestGetConfig = new TLRequestGetConfig();
            TLRequestInitConnection requestInitConnection = new TLRequestInitConnection()
            {
                ApiId = this._apiId,
                AppVersion = "1.0.0",
                DeviceModel = "PC",
                LangCode = "en",
                Query = (TLObject)requestGetConfig,
                SystemVersion = "Win 10.0"
            };
            TLRequestInvokeWithLayer invokewithLayer = new TLRequestInvokeWithLayer()
            {
                Layer = 66,
                Query = (TLObject)requestInitConnection
            };
            await this._sender.Send((TLMethod)invokewithLayer);
            byte[] numArray = await this._sender.Receive((TLMethod)invokewithLayer);
            this.dcOptions = ((TLConfig)invokewithLayer.Response).DcOptions.ToList<TLDcOption>();
        }

        private async Task ReconnectToDcAsync(int dcId)
        {
            if (this.dcOptions == null || !this.dcOptions.Any<TLDcOption>())
                throw new InvalidOperationException("Can't reconnect. Establish initial connection first.");
            TLExportedAuthorization exported = (TLExportedAuthorization)null;
            if (this._session.TLUser != null)
                exported = await this.SendRequestAsync<TLExportedAuthorization>((TLMethod)new TLRequestExportAuthorization()
                {
                    DcId = dcId
                });
            TLDcOption tlDcOption = this.dcOptions.First<TLDcOption>((Func<TLDcOption, bool>)(d => d.Id == dcId));
            DataCenter dataCenter = new DataCenter(new int?(dcId), tlDcOption.IpAddress, tlDcOption.Port);
            this._transport = new TcpTransport(tlDcOption.IpAddress, tlDcOption.Port, this._handler);
            this._session.DataCenter = dataCenter;
            await this.ConnectAsync(true);
            if (this._session.TLUser == null)
                return;
            this.OnUserAuthenticated((TLUser)(await this.SendRequestAsync<TlShema.Auth.TLAuthorization>((TLMethod)new TLRequestImportAuthorization()
            {
                Id = exported.Id,
                Bytes = exported.Bytes
            })).User);
        }

        private async Task RequestWithDcMigration(TLMethod request)
        {
            if (this._sender == null)
                throw new InvalidOperationException("Not connected!");
            bool completed = false;
            while (!completed)
            {
                try
                {
                    await this._sender.Send(request);
                    byte[] numArray = await this._sender.Receive(request);
                    completed = true;
                }
                catch (DataCenterMigrationException ex)
                {
                    if (this._session.DataCenter.DataCenterId.HasValue && this._session.DataCenter.DataCenterId.Value == ex.DC)
                        throw new Exception(string.Format("Telegram server replied requesting a migration to DataCenter {0} when this connection was already using this DataCenter", (object)ex.DC), (Exception)ex);
                    await this.ReconnectToDcAsync(ex.DC);
                    request.ConfirmReceived = false;
                }
            }
        }

        public bool IsUserAuthorized() => this._session.TLUser != null;

        public async Task<bool> IsPhoneRegisteredAsync(string phoneNumber)
        {
            TLRequestCheckPhone authCheckPhoneRequest = !string.IsNullOrWhiteSpace(phoneNumber) ? new TLRequestCheckPhone()
            {
                PhoneNumber = phoneNumber
            } : throw new ArgumentNullException(nameof(phoneNumber));
            await this.RequestWithDcMigration((TLMethod)authCheckPhoneRequest);
            return authCheckPhoneRequest.Response.PhoneRegistered;
        }

        public async Task<string> SendCodeRequestAsync(string phoneNumber)
        {
            if (string.IsNullOrWhiteSpace(phoneNumber))
                throw new ArgumentNullException(nameof(phoneNumber));
            TLRequestSendCode request = new TLRequestSendCode()
            {
                PhoneNumber = phoneNumber,
                ApiId = this._apiId,
                ApiHash = this._apiHash
            };
            await this.RequestWithDcMigration((TLMethod)request);
            return request.Response.PhoneCodeHash;
        }

        public async Task<TLUser> MakeAuthAsync(
          string phoneNumber,
          string phoneCodeHash,
          string code)
        {
            if (string.IsNullOrWhiteSpace(phoneNumber))
                throw new ArgumentNullException(nameof(phoneNumber));
            if (string.IsNullOrWhiteSpace(phoneCodeHash))
                throw new ArgumentNullException(nameof(phoneCodeHash));
            if (string.IsNullOrWhiteSpace(code))
                throw new ArgumentNullException(nameof(code));
            TLRequestSignIn request = new TLRequestSignIn()
            {
                PhoneNumber = phoneNumber,
                PhoneCodeHash = phoneCodeHash,
                PhoneCode = code
            };
            await this.RequestWithDcMigration((TLMethod)request);
            this.OnUserAuthenticated((TLUser)request.Response.User);
            return (TLUser)request.Response.User;
        }

        public async Task<TLPassword> GetPasswordSetting()
        {
            TLRequestGetPassword request = new TLRequestGetPassword();
            await this.RequestWithDcMigration((TLMethod)request);
            return (TLPassword)request.Response;
        }

        public async Task<TLUser> MakeAuthWithPasswordAsync(
          TLPassword password,
          string password_str)
        {
            byte[] hash = new SHA256Managed().ComputeHash(((IEnumerable<byte>)password.CurrentSalt).Concat<byte>((IEnumerable<byte>)Encoding.UTF8.GetBytes(password_str)).Concat<byte>((IEnumerable<byte>)password.CurrentSalt).ToArray<byte>());
            TLRequestCheckPassword request = new TLRequestCheckPassword()
            {
                PasswordHash = hash
            };
            await this.RequestWithDcMigration((TLMethod)request);
            this.OnUserAuthenticated((TLUser)request.Response.User);
            return (TLUser)request.Response.User;
        }

        public async Task<TLUser> SignUpAsync(
          string phoneNumber,
          string phoneCodeHash,
          string code,
          string firstName,
          string lastName)
        {
            TLRequestSignUp request = new TLRequestSignUp()
            {
                PhoneNumber = phoneNumber,
                PhoneCode = code,
                PhoneCodeHash = phoneCodeHash,
                FirstName = firstName,
                LastName = lastName
            };
            await this.RequestWithDcMigration((TLMethod)request);
            this.OnUserAuthenticated((TLUser)request.Response.User);
            return (TLUser)request.Response.User;
        }

        public async Task<T> SendRequestAsync<T>(TLMethod methodToExecute)
        {
            await this.RequestWithDcMigration(methodToExecute);
            return (T)methodToExecute.GetType().GetProperty("Response").GetValue((object)methodToExecute);
        }

        public async Task<TLContacts> GetContactsAsync()
        {
            if (!this.IsUserAuthorized())
                throw new InvalidOperationException("Authorize user first!");
            return await this.SendRequestAsync<TLContacts>((TLMethod)new TLRequestGetContacts()
            {
                Hash = ""
            });
        }

        public async Task<TLAbsUpdates> SendMessageAsync(
          TLAbsInputPeer peer,
          string message)
        {
            TelegramClient telegramClient = this;
            if (!telegramClient.IsUserAuthorized())
                throw new InvalidOperationException("Authorize user first!");
            return await telegramClient.SendRequestAsync<TLAbsUpdates>((TLMethod)new TLRequestSendMessage()
            {
                Peer = peer,
                Message = message,
                RandomId = Helpers.GenerateRandomLong()
            });
        }

        public async Task<bool> SendTypingAsync(TLAbsInputPeer peer) => await this.SendRequestAsync<bool>((TLMethod)new TLRequestSetTyping()
        {
            Action = (TLAbsSendMessageAction)new TLSendMessageTypingAction(),
            Peer = peer
        });

        public async Task<TLAbsDialogs> GetUserDialogsAsync(
          int offsetDate = 0,
          int offsetId = 0,
          TLAbsInputPeer offsetPeer = null,
          int limit = 100)
        {
            if (!this.IsUserAuthorized())
                throw new InvalidOperationException("Authorize user first!");
            if (offsetPeer == null)
                offsetPeer = (TLAbsInputPeer)new TLInputPeerSelf();
            return await this.SendRequestAsync<TLAbsDialogs>((TLMethod)new TLRequestGetDialogs()
            {
                OffsetDate = offsetDate,
                OffsetId = offsetId,
                OffsetPeer = offsetPeer,
                Limit = limit
            });
        }

        public async Task<TLAbsUpdates> SendUploadedPhoto(
          TLAbsInputPeer peer,
          TLAbsInputFile file,
          string caption)
        {
            return await this.SendRequestAsync<TLAbsUpdates>((TLMethod)new TLRequestSendMedia()
            {
                RandomId = Helpers.GenerateRandomLong(),
                Background = false,
                ClearDraft = false,
                Media = (TLAbsInputMedia)new TLInputMediaUploadedPhoto()
                {
                    File = file,
                    Caption = caption
                },
                Peer = peer
            });
        }

        public async Task<TLAbsUpdates> SendUploadedDocument(
          TLAbsInputPeer peer,
          TLAbsInputFile file,
          string caption,
          string mimeType,
          TLVector<TLAbsDocumentAttribute> attributes)
        {
            return await this.SendRequestAsync<TLAbsUpdates>((TLMethod)new TLRequestSendMedia()
            {
                RandomId = Helpers.GenerateRandomLong(),
                Background = false,
                ClearDraft = false,
                Media = (TLAbsInputMedia)new TLInputMediaUploadedDocument()
                {
                    File = file,
                    Caption = caption,
                    MimeType = mimeType,
                    Attributes = attributes
                },
                Peer = peer
            });
        }

        public async Task<TLFile> GetFile(
          TLAbsInputFileLocation location,
          int filePartSize,
          int offset = 0)
        {
            return await this.SendRequestAsync<TLFile>((TLMethod)new TLRequestGetFile()
            {
                Location = location,
                Limit = filePartSize,
                Offset = offset
            });
        }

        public async Task SendPingAsync() => await this._sender.SendPingAsync();

        public async Task<TLAbsMessages> GetHistoryAsync(
          TLAbsInputPeer peer,
          int offsetId = 0,
          int offsetDate = 0,
          int addOffset = 0,
          int limit = 100,
          int maxId = 0,
          int minId = 0)
        {
            if (!this.IsUserAuthorized())
                throw new InvalidOperationException("Authorize user first!");
            return await this.SendRequestAsync<TLAbsMessages>((TLMethod)new TLRequestGetHistory()
            {
                Peer = peer,
                OffsetId = offsetId,
                OffsetDate = offsetDate,
                AddOffset = addOffset,
                Limit = limit,
                MaxId = maxId,
                MinId = minId
            });
        }

        public async Task<TLFound> SearchUserAsync(string q, int limit = 10) => await this.SendRequestAsync<TLFound>((TLMethod)new TlShema.Contacts.TLRequestSearch()
        {
            Q = q,
            Limit = limit
        });

        private void OnUserAuthenticated(TLUser TLUser)
        {
            this._session.TLUser = TLUser;
            this._session.SessionExpires = int.MaxValue;
            this._session.Save();
        }

        public bool IsConnected => this._transport != null && this._transport.IsConnected;

        public void Dispose()
        {
            if (this._transport == null)
                return;
            this._transport.Dispose();
            this._transport = (TcpTransport)null;
        }
    }
}
