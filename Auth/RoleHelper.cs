using Microsoft.AspNetCore.Identity;

namespace Auth
{
    public class RoleHelper
    {
        public static async Task EnsureRolesCreated(RoleManager<IdentityRole> roleManager)
        {
            string[] roleNames = { "Admin", "User" };

            foreach (var roleName in roleNames)
            {
                var roleExist = await roleManager.RoleExistsAsync(roleName);

                if (!roleExist)
                {
                    // Create the roles and seed them to the database
                   await roleManager.CreateAsync(new IdentityRole(roleName));
                }
            }
        }
    }
}
