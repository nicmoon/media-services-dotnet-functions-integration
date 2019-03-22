/*
Azure Media Services REST API v2 Function

This function creates an authorization policy for an asset with dynamic encryption.

Input
{
    b64Secret: string;                                         // the base 64 encoded token secret
    ckdType: string;                                           // "PlayReadyLicense", "Widevine", or "FairPlay"
    tokenType: string;                                         // "JWT" or "SWT"
    audience: string;                                          // Azure Token Audience Value
    issuer: string;                                            // - Azure Token Issuer Value
    tokenClaims: { ClaimType: string, ClaimValue: string }[];  // The token claims to validate
    keyDeliveryConfiguration: string;                          // JSON/XML string of key delivery configuration
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
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace media_functions_for_logic_app
{
	public static class add_authorization_policy
	{
		private static CloudMediaContext _context = null;

		[FunctionName("add-authorization-policy")]

		public static async Task<object> Run([HttpTrigger(WebHookType = "genericJson")]HttpRequestMessage req, TraceWriter log)
		{
			log.Info($"AMS v2 Function - CreateContentKeyAuthorizationPolicy was triggered!");

			string jsonContent = await req.Content.ReadAsStringAsync();

			if (string.IsNullOrEmpty(jsonContent))
			{
				return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Please pass a JSON request body" });
			}

			dynamic data = JsonConvert.DeserializeObject(jsonContent);

			// Validate input objects
			if (data.b64Secret == null)
			{
				return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Please pass a base 64 symetric secret" });
			}

			if (data.ckdType == null)
			{
				return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Please pass the content key delivery type (PlayReadyLicense, Widevine, or FairPlay)" });
			}

			if (data.tokenType == null)
			{
				return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Please pass the token type (SWT or JWT)" });
			}

			if (data.audience == null)
			{
				return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Please pass the audience value" });
			}

			if (data.issuer == null)
			{
				return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Please pass the issuer value" });
			}

			string base64Secret = data.b64Secret ?? string.Empty;
			string contentKeyDeliveryTypeString = data.ckdType ?? string.Empty;
			string tokenTypeString = data.tokenType ?? string.Empty;
			string audience = data.audience ?? string.Empty;
			string issuer = data.issuer ?? string.Empty;
			string keyDeliveryConfiguration = data.keyDeliveryConfiguration;

			byte[] tokenSecret;
			try
			{
				tokenSecret = Convert.FromBase64String(base64Secret);
				log.Info($"Token parsed from " + base64Secret + "!");
			}
			catch
			{
				return req.CreateResponse(HttpStatusCode.BadRequest, new { error = base64Secret + "was not a valid base 64 string" });
			}
			
			ContentKeyDeliveryType contentKeyDeliveryType;
			switch (contentKeyDeliveryTypeString.Trim().ToUpper())
			{
				case "PLAYREADYLICENSE":
					contentKeyDeliveryType = ContentKeyDeliveryType.PlayReadyLicense;
					break;
				case "WIDEVINE":
					contentKeyDeliveryType = ContentKeyDeliveryType.Widevine;
					break;
				case "FAIRPLAY":
					contentKeyDeliveryType = ContentKeyDeliveryType.FairPlay;
					break;
				case "NONE":
					contentKeyDeliveryType = ContentKeyDeliveryType.None;
					break;
				case "BASELINEHTTP":
					contentKeyDeliveryType = ContentKeyDeliveryType.BaselineHttp;
					break;
				default:
					return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Please pass the content key delivery type (PlayReadyLicense, Widevine, or FairPlay)" });
			}

			log.Info($"Decided on {contentKeyDeliveryType.ToString()}!");

			TokenType tokenType;
			switch (tokenTypeString.Trim().ToUpper())
			{
				case "SWT":
					tokenType = TokenType.SWT;
					break;
				case "JWT":
					tokenType = TokenType.JWT;
					break;
				default:
					return req.CreateResponse(HttpStatusCode.BadRequest, new { error = "Please pass the content key delivery type (PlayReadyLicense, Widevine, or FairPlay)" });
			}

			log.Info($"Decided on {tokenType.ToString()}!");

			TokenClaim[] tokenClaims = data.tokenClaims;

			int count = tokenClaims == null ? 0 : tokenClaims.Length;
			log.Info($"Decided on {count} claim requirements!");

			IContentKeyAuthorizationPolicyOption result;

			try
			{
				log.Info($"Making auth policy!");
				result = await GetTokenRestrictedAuthorizationPolicyAsync(tokenSecret, contentKeyDeliveryType, tokenType, audience, issuer, tokenClaims, keyDeliveryConfiguration);
				log.Info($"Out of auth policy code");
				if (result != null)
				{
					log.Info($"Made auth policy");
				}
			}
			catch (Exception ex)
			{
				string message = ex.Message + ((ex.InnerException != null) ? Environment.NewLine + MediaServicesHelper.GetErrorMessage(ex) : "");
				log.Info($"ERROR: Exception {message}");
				return req.CreateResponse(HttpStatusCode.InternalServerError, new { error = message });
			}

			return req.CreateResponse(HttpStatusCode.OK, new
			{
				authPolicyId = result.Id,
			});

		}

		private static async Task<IContentKeyAuthorizationPolicyOption> GetTokenRestrictedAuthorizationPolicyAsync(byte[] tokenSecret, ContentKeyDeliveryType ckdTypes, TokenType tokenType,
			string audience, string issuer, TokenClaim[] tokenClaims, string keyDeliveryConfiguration)
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

			return await _context.ContentKeyAuthorizationPolicyOptions.CreateAsync(name, ckdTypes, restrictions, keyDeliveryConfiguration);
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
	}
}
