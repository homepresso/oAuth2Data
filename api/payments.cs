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

namespace K2.oAuthData
{
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
    }
}
