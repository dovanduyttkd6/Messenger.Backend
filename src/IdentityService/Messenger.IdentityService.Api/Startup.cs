namespace Messenger.IdentityService.Api;

public class Startup
{
    private readonly IConfiguration _configuration;

    public Startup(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAuthorization();
        services.AddAuthentication();
        services.AddJwtServices(_configuration);
        services.ConfigureAuthentication(_configuration);
        services.AddIdentityDatabase(_configuration);
        services.AddControllers();
        services.AddServices();
    }

    public void Configure(IApplicationBuilder app)
    {
        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
        });
    }
}