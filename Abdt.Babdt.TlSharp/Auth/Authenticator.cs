using System.Threading.Tasks;
using Abdt.Babdt.TlSharp.Network;

namespace Abdt.Babdt.TlSharp.Auth
{
  public static class Authenticator
  {
    public static async Task<Step3_Response> DoAuthentication(
      TcpTransport transport)
    {
      MtProtoPlainSender sender = new MtProtoPlainSender(transport);
      Step1_PQRequest step1 = new Step1_PQRequest();
      await sender.Send(step1.ToBytes());
      Step1_PQRequest step1PqRequest = step1;
      Step1_Response step1Response = step1PqRequest.FromBytes(await sender.Receive());
      step1PqRequest = (Step1_PQRequest) null;
      Step2_DHExchange step2 = new Step2_DHExchange();
      await sender.Send(step2.ToBytes(step1Response.Nonce, step1Response.ServerNonce, step1Response.Fingerprints, step1Response.Pq));
      Step2_DHExchange step2DhExchange = step2;
      Step2_Response step2Response = step2DhExchange.FromBytes(await sender.Receive());
      step2DhExchange = (Step2_DHExchange) null;
      Step3_CompleteDHExchange step3 = new Step3_CompleteDHExchange();
      await sender.Send(step3.ToBytes(step2Response.Nonce, step2Response.ServerNonce, step2Response.NewNonce, step2Response.EncryptedAnswer));
      Step3_CompleteDHExchange completeDhExchange = step3;
      Step3_Response step3Response = completeDhExchange.FromBytes(await sender.Receive());
      completeDhExchange = (Step3_CompleteDHExchange) null;
      return step3Response;
    }
  }
}
