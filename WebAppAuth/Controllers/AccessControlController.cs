using System;
using System.Collections.Generic;
using System.Data;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Description;
using WebAppAuth.Models;

namespace WebAppAuth.Controllers
{
    public class AccessControlController : ApiController
    {
        private DbEntities db = new DbEntities();

        // GET: api/AccessControls
        public IQueryable<AccessControl> GetAccessControls()
        {
            return db.AccessControls;
        }

        // GET: api/AccessControls/5
        [ResponseType(typeof(AccessControl))]
        public async Task<IHttpActionResult> GetAccessControl(int id)
        {
            AccessControl accessControl = await db.AccessControls.FindAsync(id);
            if (accessControl == null)
            {
                return NotFound();
            }

            return Ok(accessControl);
        }

        // PUT: api/AccessControls/5
        [ResponseType(typeof(void))]
        public async Task<IHttpActionResult> PutAccessControl(int id, AccessControl accessControl)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (id != accessControl.id)
            {
                return BadRequest();
            }

            db.Entry(accessControl).State = EntityState.Modified;

            try
            {
                await db.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!AccessControlExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }

            return StatusCode(HttpStatusCode.NoContent);
        }

        // POST: api/AccessControls
        [ResponseType(typeof(AccessControl))]
        public async Task<IHttpActionResult> PostAccessControl(AccessControl accessControl)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            db.AccessControls.Add(accessControl);
            await db.SaveChangesAsync();

            return CreatedAtRoute("DefaultApi", new { id = accessControl.id }, accessControl);
        }

        // DELETE: api/AccessControls/5
        [ResponseType(typeof(AccessControl))]
        public async Task<IHttpActionResult> DeleteAccessControl(int id)
        {
            AccessControl accessControl = await db.AccessControls.FindAsync(id);
            if (accessControl == null)
            {
                return NotFound();
            }

            db.AccessControls.Remove(accessControl);
            await db.SaveChangesAsync();

            return Ok(accessControl);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }

        private bool AccessControlExists(int id)
        {
            return db.AccessControls.Count(e => e.id == id) > 0;
        }


        /**GET Access Control BY Application     * **/

        [Route("api/acl/{app}")]
        [HttpGet, HttpPost]
        public IHttpActionResult GetFieldLangByCode(string app)
        {

            //string role = "en";
            var propertyInfo = typeof(AccessControl).GetProperty("Application");
            var result = (
                                from record in db.AccessControls.AsEnumerable().Where(a =>
                    propertyInfo.GetValue(a, null).ToString().ToLower().Contains(app.ToLower())
                )
                                select record

            ).AsQueryable();
            //ONLY RETURN THE FIRST VALUE IN THE RESULT LIST (IN CASE THERE HAPPENS TO BE TWO OF THE SAME RECORD
            return Ok(result.First());
        }
    }
}