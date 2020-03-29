//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace MachineTest
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.Web.Mvc;

    public partial class Employee
    {
        public decimal ID { get; set; }
        public string Name { get; set; }
        [DataType(DataType.Date)]
        [DisplayFormat(DataFormatString = "{0:yyyy-MM-dd}", ApplyFormatInEditMode = true)]
        public System.DateTime BirthDate { get; set; }
        public string Qualification { get; set; }
        public Nullable<decimal> Experience { get; set; }
        [DataType(DataType.Date)]
        [DisplayFormat(DataFormatString = "{0:yyyy-MM-dd}", ApplyFormatInEditMode = true)]
        public System.DateTime JoinningDate { get; set; }
        public decimal Salary { get; set; }
        public string Designation { get; set; }
        public string Hobbies { get; set; }
        public string Password { get; set; }

        public Qualification1 QualificationList { get; set; }
        public Hobbies1 HobbiesList { get; set; }

        public enum Qualification1
        {
            
            Bsc,
            BA,
            MCA,
            ME
            
        }
        public enum Hobbies1
        {

            Reading,
            Swimming
        }
    }
    public class CheckModel
    {
        public int Id { get; set; }
        public string Hobbies { get; set; }

        public bool Checked { get; set; }
    }
}
