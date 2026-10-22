using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Auth
{
    public class DbContet : IdentityDbContext<ApplicationUser>
    {
        public DbContet(DbContextOptions<DbContet> options) : base(options) { }

        override protected void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<ApplicationUser>(entity =>
            {
                entity.ToTable(name: "Users");
                entity.Property(e => e.FirstName).HasMaxLength(100);
                entity.Property(e => e.lastName).HasMaxLength(100);
            });

            builder.Entity<IdentityRole>(entity =>
            {
                entity.ToTable(name: "Roles");
            });



        }
    }
}