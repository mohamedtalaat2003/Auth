using Auth.Controllers;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Auth
{
    public class AuthDbContet : IdentityDbContext<ApplicationUser>
    {
        public AuthDbContet(DbContextOptions<AuthDbContet> options) : base(options) { }

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

            builder.Entity<RefreshToken>(entity =>
            {
                entity.ToTable("RefreshTokens");
                entity.HasKey(x => x.Id);

                entity.HasIndex(x => x.TokenHash).IsUnique();

                entity.HasOne(x => x.User)
                .WithMany(x => x.RefreshTokens)
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<ExternalLoginCode>(entity =>
            {
                entity.HasKey(x => x.Id);
                entity.Property(x => x.CodeHash)
                .HasMaxLength(100)
                .IsRequired();

                entity.Property(x => x.BrowserBindingHash)
                .HasMaxLength(100)
                .IsRequired();

                entity.HasIndex(x => x.CodeHash);

                entity.HasOne(x => x.User)
                .WithMany()
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Cascade);
            });
        }

        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<ExternalLoginCode> externalLoginCodes { get; set; }


    }
  }
