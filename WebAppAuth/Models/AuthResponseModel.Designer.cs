namespace WebAppAuth.Models
{
    using System;
    using System.Collections.Generic;
    using System.Data.Entity;
    using System.Linq;

    public class AuthResponseModel
    {
        public string Authorized { get; set; } = "";
        public string Message { get; set; } = "";
        public string UserDisplayName { get; set; } = "";
        public string LoggedOn { get; set; } = "";
        public string Admin { get; set; } = "";
        public string IT { get; set; } = "";
        public string Application { get; set; } = "";
        public string UserEmailAddress { get; set; } = "";
    }

}