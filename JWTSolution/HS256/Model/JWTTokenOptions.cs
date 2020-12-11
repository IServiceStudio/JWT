using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace HS256.Model
{
    public class JWTTokenOptions
    {
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public string SecurityKey { get; set; }
    }
}
