//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace WebAppAuth.Models
{
    using System;
    using System.Collections.Generic;
    
    public partial class AccessControl
    {
        public int id { get; set; }
        public string Application { get; set; }
        public string Discription { get; set; }
        public string Groups { get; set; }
        public string GroupsAdmin { get; set; }
        public string GroupsIT { get; set; }
    }
}