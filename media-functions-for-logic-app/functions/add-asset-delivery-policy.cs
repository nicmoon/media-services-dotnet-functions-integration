/*
Azure Media Services REST API v2 Function

This function creates a FairPlay Asset Delivery policy for an asset with dynamic encryption.

Input
{
// empty object
}

Output
{
	assetDeliveryPolicyId: string; // the asset delivery policy Id
	contentKeyId: string;          // the content key Id
	hexIv: string;                 // the Hex IV
}
*/

using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.WindowsAzure.MediaServices.Client;
using Microsoft.WindowsAzure.MediaServices.Client.ContentKeyAuthorization;
using Microsoft.WindowsAzure.MediaServices.Client.DynamicEncryption;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace media_functions_for_logic_app
{
	public static class add_asset_delivery_policy
	{
		[FunctionName("add-asset-delivery-policy")]

		public static async Task<object> Run([HttpTrigger(WebHookType = "genericJson")]HttpRequestMessage req, TraceWriter log)
		{
			log.Info($"AMS v2 Function - CreateContentKeyAuthorizationPolicy was triggered!");

			string jsonContent = await req.Content.ReadAsStringAsync();

			if (string.IsNullOrEmpty(jsonContent))
			{
				return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Please pass a JSON request body" });
			}

			object data = JsonConvert.DeserializeObject(jsonContent);

			string hexIv = GetHexIV();

			IAssetDeliveryPolicy result;
			IContentKey contentKey;

			try
			{
				result = CreateFairplayAssetDeliveryPolicy(hexIv, out contentKey);
			}
			catch (Exception ex)
			{
				string message = ex.Message + ((ex.InnerException != null) ? Environment.NewLine + MediaServicesHelper.GetErrorMessage(ex) : "") + "\n" + ex.StackTrace;
				log.Info($"ERROR: Exception {message}");
				return req.CreateResponse(HttpStatusCode.InternalServerError, new { error = message });
			}

			return req.CreateResponse(HttpStatusCode.OK, new
			{
				assetDeliveryPolicyId = result.Id,
				contentKeyId = contentKey.Id,
				hexIv = hexIv,
			});

		}

		public static IAssetDeliveryPolicy CreateFairplayAssetDeliveryPolicy(string hexIv, out IContentKey contentKey)
		{
			MediaServicesCredentials amsCredentials = new MediaServicesCredentials();
			AzureAdTokenCredentials tokenCredentials = new AzureAdTokenCredentials(amsCredentials.AmsAadTenantDomain,
					new AzureAdClientSymmetricKey(amsCredentials.AmsClientId, amsCredentials.AmsClientSecret),
					AzureEnvironments.AzureCloudEnvironment);
			AzureAdTokenProvider tokenProvider = new AzureAdTokenProvider(tokenCredentials);
			CloudMediaContext context = new CloudMediaContext(amsCredentials.AmsRestApiEndpoint, tokenProvider);

			contentKey = MakeContentKey(context, ContentKeyType.CommonEncryptionCbcs);

			Uri acquisitionUrl = contentKey.GetKeyDeliveryUrl(ContentKeyDeliveryType.FairPlay);

			Dictionary<AssetDeliveryPolicyConfigurationKey, string> assetDeliveryPolicyConfiguration =
				new Dictionary<AssetDeliveryPolicyConfigurationKey, string>
			{
				{ AssetDeliveryPolicyConfigurationKey.FairPlayBaseLicenseAcquisitionUrl, acquisitionUrl.ToString() },
				{ AssetDeliveryPolicyConfigurationKey.CommonEncryptionIVForCbcs, hexIv },
			};

			return context.AssetDeliveryPolicies.Create(
					"FairPlay AssetDeliveryPolicy",
				AssetDeliveryPolicyType.DynamicCommonEncryption,
				AssetDeliveryProtocol.HLS,
				assetDeliveryPolicyConfiguration);
		}

		public static IContentKey MakeContentKey(CloudMediaContext context, ContentKeyType contentKeyType, string contentKeyId = null, string contentKeySecret = null)
		{
			string contentKeyName;
			switch (contentKeyType)
			{
				case ContentKeyType.CommonEncryption:
					contentKeyName = "Common Encryption ContentKey";
					return MediaServicesHelper.CreateContentKey(context, contentKeyName, ContentKeyType.CommonEncryption, contentKeyId, contentKeySecret);
				case ContentKeyType.CommonEncryptionCbcs:
					contentKeyName = "Common Encryption CBCS ContentKey";
					return MediaServicesHelper.CreateContentKey(context, contentKeyName, ContentKeyType.CommonEncryptionCbcs, contentKeyId, contentKeySecret);
				case ContentKeyType.EnvelopeEncryption:
					contentKeyName = "Envelope Encryption ContentKey";
					return MediaServicesHelper.CreateContentKey(context, contentKeyName, ContentKeyType.EnvelopeEncryption, contentKeyId, contentKeySecret);
			}

			throw new NotImplementedException(contentKeyType.ToString() + " is not supported");
		}

		public static string GetHexIV()
		{
			byte[] output = MediaServicesHelper.GetRandomBuffer(16);
			return BitConverter.ToString(output).Replace("-", string.Empty);
		}
	}
}
