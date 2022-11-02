using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Runtime.Serialization;
using System.Net;
using System.Runtime.Serialization.Json;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Extensions.Primitives;
using System.Security.Claims;

namespace K2.oAuthData
{

    public class MicrosoftIdentityClient
{
    private static readonly HttpClient httpClient = new HttpClient();
    private static readonly string hostUrl = "https://login.microsoftonline.com";
 
    private readonly string tenantId;
    private readonly string clientId;
    private readonly string clientSecret;
 
    public MicrosoftIdentityClient(string clientId, string clientSecret, string tenantId)
    {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.tenantId = tenantId;
    }

    public async Task<string> GetAccessTokenFromAuthorizationCode(string authCode)
{
    string redirectUrl = "https://localhost/auth";
    string scopes = "openid offline_access https://graph.microsoft.com/user.read";
 
    Uri requestUri = new Uri($"{hostUrl}/{this.tenantId}/oauth2/v2.0/token");
 
    List<KeyValuePair<string, string>> content = new List<KeyValuePair<string, string>>()
    {
        new KeyValuePair<string, string>("client_id", this.clientId),
        new KeyValuePair<string, string>("scope", scopes),
        new KeyValuePair<string, string>("grant_type", "authorization_code"),
        new KeyValuePair<string, string>("code", authCode),
        new KeyValuePair<string, string>("redirect_uri", redirectUrl),
        new KeyValuePair<string, string>("client_secret", this.clientSecret)
    };
 
    HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, requestUri)
    {
        Content = new FormUrlEncodedContent(content),
    };
 
    HttpResponseMessage response = await httpClient.SendAsync(request);
 
    string responseContent = await response.Content.ReadAsStringAsync();
    dynamic responseObject = JsonConvert.DeserializeObject(responseContent);
 
    if (response.IsSuccessStatusCode)
    {
        // dynamic values need to be assigned before passing back
        return (string)responseObject.access_token;
    }
    else if (response.StatusCode == HttpStatusCode.BadRequest)
    {
        // Something failed along the way, and there will be an error in there if the error code is 400
        // Handle it however you want.
        throw new Exception((string)responseObject.error_description);
    }
    else
    {
        // ¯\_(ツ)_/¯
        Console.WriteLine(responseContent);
        Console.WriteLine(response.StatusCode);
        throw new Exception("Something bad happened");
    }
}
}
    public static class oAuth2Data
    {
              public class K2Body

        {

            public string Name {get; set;}

            public decimal Value {get; set;}

            public string Stage {get; set;}

            public string Recipient {get; set;}

            public string ID {get; set;}

        }


        [FunctionName("payments")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            Random rnd = new Random();

            string ID = req.Query["ID"];
            var RandNames = new List<string>{"ABC", "Stuff.co.nz", "BBC", "ACME", "Fantastic Smoothies", "Milky Coffee"};
            int index = rnd.Next(RandNames.Count);

            K2Body r = new K2Body
            {
             Stage = "Open",
             Recipient = "andy.hayes@safalo.com",
             Name = RandNames[index],
             ID = rnd.Next(100000000).ToString(),
             Value = rnd.Next(100, 2000)

            };

            return new OkObjectResult(r);
        }

        [FunctionName("HttpTriggerIdentity")]
public static async Task<IActionResult> RunTrigger(
    [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
    ILogger log)
{
 
    // Get the authentication code from the request payload
    string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
    dynamic data = JsonConvert.DeserializeObject(requestBody);
    string authCode = data.authCode;
 
    // Get the Application details from the settings
    string tenantId = Environment.GetEnvironmentVariable("TenantId", EnvironmentVariableTarget.Process);
    string clientId = Environment.GetEnvironmentVariable("ClientId", EnvironmentVariableTarget.Process);
    string clientSecret = Environment.GetEnvironmentVariable("ClientSecret", EnvironmentVariableTarget.Process);
 
    // Get the access token from MS Identity
    MicrosoftIdentityClient idClient = new MicrosoftIdentityClient(clientId, clientSecret, tenantId);
    string accessToken = await idClient.GetAccessTokenFromAuthorizationCode(authCode);
 
    return new OkObjectResult(accessToken);
}

[FunctionName("AuthHttpTrigger")]
public static IActionResult Run(HttpRequest req, ILogger log, ClaimsPrincipal principal)
{
    log.LogInformation("C# HTTP trigger function processed a request.");

    log.LogInformation($"Identity is: {principal.Identity.Name}, isAuthenticated = {principal.Identity.IsAuthenticated}");
    return new OkObjectResult($"Identity is: {principal.Identity.Name}, isAuthenticated = {principal.Identity.IsAuthenticated}");
}

        
    }
    

    
}


