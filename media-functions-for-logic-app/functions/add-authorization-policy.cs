/*
Azure Media Services REST API v2 Function

This function creates an authorization policy for an asset with dynamic encryption.

Input
{
    b64Secret: string;                                         // the base 64 encoded token secret
    tokenType: string;                                         // "JWT" or "SWT"
	contentKey: string;                                        // "CENC", "CENCcbcs", or "AES"
    audience: string;                                          // Azure Token Audience Value
    issuer: string;                                            // - Azure Token Issuer Value
    tokenClaims: { ClaimType: string, ClaimValue: string }[];  // The token claims to validate
	config: {
		ckdType: string;                                       // "PlayReadyLicense", "Widevine", or "FairPlay"
		keyDeliveryConfiguration: string;                      // JSON/XML string of key delivery configuration
	}[];
}

Output
{
    authPolicyId: string;                                      // The authentication policy ID
}
*/

using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.WindowsAzure.MediaServices.Client;
using Microsoft.WindowsAzure.MediaServices.Client.ContentKeyAuthorization;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace media_functions_for_logic_app
{
	public static class add_authorization_policy
	{
		[FunctionName("add-authorization-policy")]

		public static async Task<object> Run([HttpTrigger(WebHookType = "genericJson")]HttpRequestMessage req, TraceWriter log)
		{
			log.Info($"AMS v2 Function - CreateContentKeyAuthorizationPolicy was triggered!");

			string jsonContent = await req.Content.ReadAsStringAsync();

			if (string.IsNullOrEmpty(jsonContent))
			{
				return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Please pass a JSON request body" });
			}

			AuthorizationPolicyRequst data = JsonConvert.DeserializeObject<AuthorizationPolicyRequst>(jsonContent);

			// Validate input objects
			if (string.IsNullOrEmpty(data.b64Secret))
			{
				return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Please pass a base 64 symetric secret" });
			}

			if (string.IsNullOrEmpty(data.tokenType))
			{
				return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Please pass the token type (SWT or JWT)" });
			}

			if (string.IsNullOrEmpty(data.audience))
			{
				return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Please pass the audience value" });
			}

			if (string.IsNullOrEmpty(data.issuer))
			{
				return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Please pass the issuer value" });
			}

			if (data.config == null || data.config.Length < 1)
			{
				return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Please pass the authorization option configuration" });
			}

			IContentKeyAuthorizationPolicy result;

			try
			{
				result = GetTokenRestrictedAuthorizationPolicy(log, data);
				log.Info($"Out of auth policy code");
				if (result != null)
				{
					log.Info($"Made auth policy");
				}
			}
			catch (Exception ex)
			{
				string message = ex.Message + ((ex.InnerException != null) ? Environment.NewLine + MediaServicesHelper.GetErrorMessage(ex) : "") + "\n" + ex.StackTrace;
				log.Info($"ERROR: Exception {message}");
				return req.CreateResponse(HttpStatusCode.InternalServerError, new { error = message });
			}

			return req.CreateResponse(HttpStatusCode.OK, new
			{
				authPolicyId = result.Id,
			});

		}

		private static IContentKeyAuthorizationPolicy GetTokenRestrictedAuthorizationPolicy(TraceWriter log, AuthorizationPolicyRequst request)
		{
			MediaServicesCredentials amsCredentials = new MediaServicesCredentials();
			AzureAdTokenCredentials tokenCredentials = new AzureAdTokenCredentials(amsCredentials.AmsAadTenantDomain,
					new AzureAdClientSymmetricKey(amsCredentials.AmsClientId, amsCredentials.AmsClientSecret),
					AzureEnvironments.AzureCloudEnvironment);
			AzureAdTokenProvider tokenProvider = new AzureAdTokenProvider(tokenCredentials);
			CloudMediaContext context = new CloudMediaContext(amsCredentials.AmsRestApiEndpoint, tokenProvider);

			byte[] secret = request.tokenSecret;
			TokenClaim[] tokenClaims = request.tokenClaims;
			TokenType tokenType = request.TokenTypeEnum;
			string audience = request.audience;
			string issuer = request.issuer;

			List<IContentKeyAuthorizationPolicyOption> authPolicyOptions = new List<IContentKeyAuthorizationPolicyOption>(request.config.Length);
			List<ContentKeyDeliveryType> delTypes = new List<ContentKeyDeliveryType>(request.config.Length);

			log.Info($"Prepared for auth policy loop on {request.config.Length} entries with: {(secret ?? new byte[0]).Length} long key; {(tokenClaims ?? new TokenClaim[0]).Length} claims; {tokenType.ToString()} {audience} {issuer}");

			// return 
			foreach (AuthorizationPolicyRequestTokenConfig d in request.config)
			{
				ContentKeyDeliveryType ckdType = d.ContentKeyDeliveryType;
				delTypes.Add(ckdType);
				log.Info($"Making auth policy option! {d.ContentKeyDeliveryType.ToString()} {d.keyDeliveryConfiguration}");
				IContentKeyAuthorizationPolicyOption option = GetTokenRestrictedAuthorizationPolicyOption(context, secret, ckdType, tokenType, audience, issuer, tokenClaims, d.keyDeliveryConfiguration);
				authPolicyOptions.Add(option);
			}

			log.Info($"Making policy container");
			IContentKeyAuthorizationPolicy policy = context.ContentKeyAuthorizationPolicies.CreateAsync(string.Join(", ", delTypes.Select(x => x.ToString())) + " Authentication Policy").Result;

			foreach (IContentKeyAuthorizationPolicyOption a in authPolicyOptions)
			{
				log.Info($"Adding policy " + a.Name);
				policy.Options.Add(a);
			}

			return policy;
		}

		private static byte[] GetRandomBuffer(int size)
		{
			byte[] randomBytes = new byte[size];
			using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
			{
				rng.GetBytes(randomBytes);
			}

			return randomBytes;
		}

		private static IContentKeyAuthorizationPolicyOption GetTokenRestrictedAuthorizationPolicyOption(CloudMediaContext context, byte[] tokenSecret,
			ContentKeyDeliveryType ckdTypes, TokenType tokenType, string audience, string issuer, TokenClaim[] tokenClaims, string keyDeliveryConfiguration)
		{
			string tokenTemplateString = GenerateTokenRequirements(tokenSecret, tokenType, audience, issuer, tokenClaims);

			List<ContentKeyAuthorizationPolicyRestriction> restrictions = new List<ContentKeyAuthorizationPolicyRestriction>
			{
				new ContentKeyAuthorizationPolicyRestriction
				{
					Name = "Token Authorization Policy",
					KeyRestrictionType = (int)ContentKeyRestrictionType.TokenRestricted,
					Requirements = tokenTemplateString,
				}
			};

			string name;

			switch (ckdTypes)
			{
				case ContentKeyDeliveryType.PlayReadyLicense:
					name = "Playready License";
					break;
				case ContentKeyDeliveryType.Widevine:
					name = "Widevine License";
					break;
				case ContentKeyDeliveryType.FairPlay:
					name = "FairPlay License";
					break;
				default:
					throw new NotSupportedException("We do not support " + ckdTypes.ToString());
			}

			return context.ContentKeyAuthorizationPolicyOptions.Create(name, ckdTypes, restrictions, keyDeliveryConfiguration);
		}

		static private string GenerateTokenRequirements(byte[] tokenSecret, TokenType tokenType, string audience, string issuer, TokenClaim[] tokenClaims)
		{
			TokenRestrictionTemplate template = new TokenRestrictionTemplate(tokenType)
			{
				PrimaryVerificationKey = new SymmetricVerificationKey(tokenSecret),
				Audience = audience,
				Issuer = issuer,
			};

			// template.AlternateVerificationKeys.Add(new SymmetricVerificationKey());
			// could add an alternate key here, but easy to just share secret with other sites since we use only one

			if (tokenClaims != null)
			{
				foreach (TokenClaim claim in tokenClaims)
				{
					template.RequiredClaims.Add(claim);
				}
			}

			return TokenRestrictionTemplateSerializer.Serialize(template);
		}

		private class AuthorizationPolicyRequst
		{
			public string b64Secret { get; set; }
			public byte[] tokenSecret
			{
				get
				{
					return Convert.FromBase64String(b64Secret);
				}
			}
			public string tokenType { get; set; }
			public TokenType TokenTypeEnum
			{
				get
				{
					switch (tokenType.Trim().ToUpper())
					{
						case "SWT":
							return TokenType.SWT;
						case "JWT":
							return TokenType.JWT;
						default:
							throw new FormatException((tokenType ?? "<null>") + " was not a valid token type; please pass JWT or SWT");
					}
				}
			}
			public string contentKey { get; set; }
			public ContentKeyType ContentKeyType
			{
				get
				{
					// Conver to uppercase and remove all spaces
					switch (string.Join("", contentKey.ToUpper().Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries)))
					{
						case "COMMONENCRYPTION":
						case "CENC":
							return ContentKeyType.CommonEncryption;
						case "COMMONENCRYPTIONCBCS":
						case "CENCCBCS":
							return ContentKeyType.CommonEncryptionCbcs;
						case "ENVELOPE":
						case "AES":
							return ContentKeyType.EnvelopeEncryption;
						default:
							throw new FormatException((contentKey ?? "<null>") + " was not a valid content key type; please pass CENC, CENCcbcs, or AES");
					}
				}
			}
			public string audience { get; set; }
			public string issuer { get; set; }
			public TokenClaim[] tokenClaims { get; set; }
			public AuthorizationPolicyRequestTokenConfig[] config { get; set; }
		}

		private class AuthorizationPolicyRequestTokenConfig
		{
			public string ckdType { get; set; }
			public ContentKeyDeliveryType ContentKeyDeliveryType
			{
				get
				{
					switch (ckdType.Trim().ToUpper())
					{
						case "PLAYREADY":
						case "PLAYREADYLICENSE":
							return ContentKeyDeliveryType.PlayReadyLicense;
						case "WIDEVINE":
							return ContentKeyDeliveryType.Widevine;
						case "FAIRPLAY":
							return ContentKeyDeliveryType.FairPlay;
						case "NONE":
							return ContentKeyDeliveryType.None;
						case "BASELINEHTTP":
							return ContentKeyDeliveryType.BaselineHttp;
						default:
							throw new FormatException((ckdType ?? "<null>") + " is not supported; pass PlayReadyLicense, Widevine, or FairPlay");
					}
				}
			}
			public string keyDeliveryConfiguration { get; set; }
		}
	}
}
