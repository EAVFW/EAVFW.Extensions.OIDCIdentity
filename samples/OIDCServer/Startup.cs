using EAVFramework;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ModelGenerationTest;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Server.AspNetCore;
using OpenIddict;
using OpenIddict.Server;
using OpenIddict.Core;
using System.IO;
using Newtonsoft.Json.Linq;
using MC.Models;
using EAVFW.Extensions.SecurityModel;
using EAVFramework.Extensions;
using OpenIddict.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using EAVFW.Extensions.OIDCIdentity;
using static OpenIddict.Abstractions.OpenIddictConstants;
using System.Security.Claims;

namespace OIDCServer
{
    public class EAVClientManager : ClientManager<OpenIdConnectClient, AllowedGrantType, OpenIdConnectClientTypes, OpenIdConnectClientConsentTypes, AllowedGrantTypeValue>
    {
        public EAVClientManager(IOpenIddictApplicationCache<OpenIdConnectClient> cache, ILogger<OpenIddictApplicationManager<OpenIdConnectClient>> logger, IOptionsMonitor<OpenIddictCoreOptions> options, IOpenIddictApplicationStoreResolver resolver) : base(cache, logger, options, resolver)
        {
        }
    }

    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Register<DynamicContext, EAVClientManager>();
             

            services.AddOptions<DynamicContextOptions>().Configure<IWebHostEnvironment>((o, environment) =>
            {

                o.Manifests = new[]{ 
                    
                          JToken.Parse(File.ReadAllText($@"C:\dev2\EAVFW.Extensions.OIDCIdentity\tests\ModelGenerationTest\obj\manifest.g.json"))
                };


                o.PublisherPrefix = "MC";
                o.EnableDynamicMigrations = true;
                o.Namespace = "Kjeldager.Models";
                o.DTOAssembly = typeof(Server).Assembly;

                o.DTOBaseClasses = new Type[] {
                     typeof(BaseOwnerEntity<Identity>),
                     typeof(BaseIdEntity<Identity>)
                };


            });

            //   services.AddRazorPages();
            services.AddEAVFramework<DynamicContext>(o =>
            {
                o.RoutePrefix = "/api";
            }).WithAuditFieldsPlugins<DynamicContext, Identity>();
            services.AddDbContext<DynamicContext>((sp, optionsBuilder) =>
            {
                
              
                optionsBuilder.UseSqlServer("Name=ApplicationDb",
                    x => x.MigrationsHistoryTable("__MigrationsHistory", "dbo").EnableRetryOnFailure()
                        .CommandTimeout(180));

                optionsBuilder.UseInternalServiceProvider(sp);
                optionsBuilder.EnableSensitiveDataLogging();
                optionsBuilder.EnableDetailedErrors();
            });

          
            services.AddAuthorization();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

          
           
            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapGet("/clients/{clientid}/secret", async r => {

                   

                    var cm = r.RequestServices.GetRequiredService<EAVClientManager>();
                    var client = await cm.FindByClientIdAsync(r.Request.RouteValues["clientid"].ToString());
                   
                    r.User = new ClaimsPrincipal(new ClaimsIdentity(new Claim[] {
                                   new Claim("sub",client.Id.ToString())
                                }, EAVFramework.Constants.DefaultCookieAuthenticationScheme));

                    var secret= Guid.NewGuid().ToString(); ;
                    client.ClientSecret = await cm.ObfuscateClientSecretAsync( secret);
                    await cm.UpdateAsync(client);
                 
                    //cm.GetAsync()

                    await r.Response.WriteJsonAsync(new { secret=secret});
                    
                    
                    });
               // endpoints.MapRazorPages();
            });
        }
    }
}
