using EAVFramework;
using EAVFramework.Endpoints;
using EAVFW.Extensions.OIDCIdentity;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Data;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;


namespace EAVFW.Extensions.OIDCIdentity
{

    public class OpenIddictEAVFrameowrkApplicationStore<
        TContext,
        TOpenIdConnectClient,
        TOpenIdConnectAuthorization,
        TOpenIdConnectAuthorizationStatus,
        TOpenIdConnectAuthorizationType,
        TOpenIdConnectToken,
        TOpenIdConnectTokenStatus,
        TOpenIdConnectTokenType,
        TAllowedGrantType,
        TOpenIdConnectAuthorizationScope,
        TOpenIdConnectClientTypes,
        TOpenIdConnectClientConsentTypes,
        TAllowedGrantTypeValue,
        TOpenIdConnectScope, TOpenIdConnectScopeResource, TOpenIdConnectResource, TOpenIdConnectIdentityResource
        > :
        OIDConnectStore<
            TContext,
            TOpenIdConnectClient,
            TOpenIdConnectAuthorization,
            TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType,
            TOpenIdConnectToken,
            TOpenIdConnectTokenType,
            TOpenIdConnectTokenStatus,
            TAllowedGrantType,
            TOpenIdConnectAuthorizationScope,
            TOpenIdConnectClientTypes,
            TOpenIdConnectClientConsentTypes,
            TAllowedGrantTypeValue,
            TOpenIdConnectScope, TOpenIdConnectScopeResource, TOpenIdConnectResource, TOpenIdConnectIdentityResource
        >,
        IOpenIddictApplicationStore<TOpenIdConnectClient>

        where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes>
        where TOpenIdConnectAuthorization : DynamicEntity, IOpenIdConnectAuthorization<TOpenIdConnectClient, TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType>
        where TOpenIdConnectAuthorizationStatus : struct, IConvertible
        where TOpenIdConnectToken : DynamicEntity, IOpenIdConnectToken<TOpenIdConnectClient, TOpenIdConnectAuthorization, TOpenIdConnectTokenStatus, TOpenIdConnectTokenType>
        where TOpenIdConnectTokenStatus : struct, IConvertible
        where TOpenIdConnectTokenType : struct, IConvertible
        where TAllowedGrantType : DynamicEntity, IAllowedGrantType<TAllowedGrantTypeValue>
        where TOpenIdConnectAuthorizationScope : DynamicEntity, IOpenIdConnectAuthorizationScope<TOpenIdConnectIdentityResource>, new()
        where TOpenIdConnectClientTypes : struct, IConvertible
        where TOpenIdConnectClientConsentTypes : struct, IConvertible
        where TAllowedGrantTypeValue : struct, IConvertible
            where TOpenIdConnectScopeResource : DynamicEntity, IOpenIdConnectScopeResource<TOpenIdConnectResource, TOpenIdConnectIdentityResource>
            where TOpenIdConnectResource : DynamicEntity, IOpenIdConnectResource
    where TOpenIdConnectScope : DynamicEntity, IOpenIdConnectScope<TOpenIdConnectScopeResource>
        where TOpenIdConnectIdentityResource : DynamicEntity, IOpenIdConnectIdentityResource
         where TOpenIdConnectAuthorizationType : struct, IConvertible
        where TContext : DynamicContext
    {
        public OpenIddictEAVFrameowrkApplicationStore(
            IMemoryCache cache,
          IPrincipalService<
            TOpenIdConnectAuthorization,
            TOpenIdConnectClient,
            TAllowedGrantType,
            TAllowedGrantTypeValue,
            TOpenIdConnectClientTypes,
            TOpenIdConnectClientConsentTypes,
            TOpenIdConnectAuthorizationStatus,
            TOpenIdConnectAuthorizationType,
            TOpenIdConnectAuthorizationScope,
            TOpenIdConnectIdentityResource,
            TOpenIdConnectToken,
            TOpenIdConnectTokenStatus,
            TOpenIdConnectTokenType,
            TOpenIdConnectScopeResource,
            TOpenIdConnectResource,
            TOpenIdConnectScope
            > principalService, EAVDBContext<TContext> context,
            IOptionsMonitor<OpenIddictEAVFrameworkOptions> options) : base(cache, principalService, context, options)
        {

        }


        private IQueryable<TOpenIdConnectClient> Loader => Applications.Include(c => c.AllowedGrantTypes).AsTracking();
        /// <inheritdoc/>
        public virtual async ValueTask<long> CountAsync(CancellationToken cancellationToken)
            => await Applications.AsQueryable().LongCountAsync(cancellationToken);


        /// <inheritdoc/>
        public virtual async ValueTask<long> CountAsync<TResult>(Func<IQueryable<TOpenIdConnectClient>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            if (query is null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return await query(Applications).LongCountAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual async ValueTask CreateAsync(TOpenIdConnectClient application, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            Context.Context.Add(application);

            await Context.SaveChangesAsync(await PrincipalService.CreatePrincipalForClient());
        }

        /// <inheritdoc/>
        public virtual async ValueTask DeleteAsync(TOpenIdConnectClient application, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }




            //Task<List<TOpenIdConnectAuthorization>> ListAuthorizationsAsync()
            //    => (from authorization in Authorizations
            //        .Include(authorization => authorization.OpenIdConnectTokens)
            //        .AsTracking()
            //        where authorization.ClientId == application.Id
            //        select authorization).ToListAsync(cancellationToken);

            Task<List<TOpenIdConnectToken>> ListTokensByAuthorizationAsync() =>
                Tokens.Include(a=>a.Authorization).Where(t=>t.Authorization.ClientId == application.Id)
                
                .ToListAsync(cancellationToken);


            Task<List<TOpenIdConnectToken>> ListTokensAsync()
                => (from token in Tokens.AsTracking()
                    where token.Authorization == null && token.ClientId == application.Id
                    select token).ToListAsync(cancellationToken);

            // To prevent an SQL exception from being thrown if a new associated entity is
            // created after the existing entries have been listed, the following logic is
            // executed in a serializable transaction, that will lock the affected tables.
            using var transaction = await Context.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

            // Remove all the authorizations associated with the application and
            // the tokens attached to these implicit or explicit authorizations.
            var authorizations = await ListTokensByAuthorizationAsync();
            foreach (var authorization in authorizations.GroupBy(c=>c.Authorization))
            {
                foreach (var token in authorization)
                {
                    Context.Remove(token);
                }

                Context.Remove(authorization.Key);
            }

            // Remove all the tokens associated with the application.
            var tokens = await ListTokensAsync();
            foreach (var token in tokens)
            {
                Context.Remove(token);
            }

            Context.Remove(application);

            try
            {
                await Context.SaveChangesAsync(await PrincipalService.CreatePrincipalForDeleteClient());
                transaction?.Commit();
            }

            catch (DbUpdateConcurrencyException exception)
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                Context.ResetEntryTracking(application); // Context.Entry(application).State = EntityState.Unchanged;
                Context.ResetEntryTracking(authorizations);
                Context.ResetEntryTracking(tokens);

                //foreach (var authorization in authorizations)
                //{
                //    Context.ResetEntryTacking(authorization);//  Context.Entry(authorization).State = EntityState.Unchanged;
                //}

                //foreach (var token in tokens)
                //{
                //    Context.ResetEntryTacking(token);// Context.Entry(token).State = EntityState.Unchanged;
                //}

                throw new OpenIddictExceptions.ConcurrencyException(
@"SR.ID0239 : The application was concurrently updated and cannot be persisted in its current state.
Reload the application from the database and retry the operation.", exception);
            }
        }

        /// <inheritdoc/>
        public virtual async ValueTask<TOpenIdConnectClient?> FindByClientIdAsync(string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
            }

            return await (from application in Loader
                          where application.ClientId == identifier
                          select application).FirstOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual async ValueTask<TOpenIdConnectClient?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException("The identifier cannot be null or empty.", nameof(identifier));
            }

            var key = Guid.Parse(identifier);

            return await (from application in Loader
                          where application.Id == key
                          select application).FirstOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectClient> FindByPostLogoutRedirectUriAsync(
            string address, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0143), nameof(address));
            }

            // To optimize the efficiency of the query a bit, only applications whose stringified
            // PostLogoutRedirectUris contains the specified URL are returned. Once the applications
            // are retrieved, a second pass is made to ensure only valid elements are returned.
            // Implementers that use this method in a hot path may want to override this method
            // to use SQL Server 2016 functions like JSON_VALUE to make the query more efficient.

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<TOpenIdConnectClient> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                var applications = (from application in Loader
                                    where application.PostLogoutRedirectURIs!.Contains(address)
                                    select application).AsAsyncEnumerable(cancellationToken);

                await foreach (var application in applications)
                {
                    var addresses = await GetPostLogoutRedirectUrisAsync(application, cancellationToken);
                    if (addresses.Contains(address, StringComparer.Ordinal))
                    {
                        yield return application;
                    }
                }
            }
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectClient> FindByRedirectUriAsync(
            string address, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(address))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0143), nameof(address));
            }

            // To optimize the efficiency of the query a bit, only applications whose stringified
            // RedirectUris property contains the specified URL are returned. Once the applications
            // are retrieved, a second pass is made to ensure only valid elements are returned.
            // Implementers that use this method in a hot path may want to override this method
            // to use SQL Server 2016 functions like JSON_VALUE to make the query more efficient.

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<TOpenIdConnectClient> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                var applications = (from application in Loader
                                    where application.RedirectUris!.Contains(address)
                                    select application).AsAsyncEnumerable(cancellationToken);

                await foreach (var application in applications)
                {
                    var addresses = await GetRedirectUrisAsync(application, cancellationToken);
                    if (addresses.Contains(address, StringComparer.Ordinal))
                    {
                        yield return application;
                    }
                }
            }
        }

        /// <inheritdoc/>
        public virtual async ValueTask<TResult> GetAsync<TState, TResult>(
            Func<IQueryable<TOpenIdConnectClient>, TState, IQueryable<TResult>> query,
            TState state, CancellationToken cancellationToken)
        {
            if (query is null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return await query(Loader, state).FirstOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetClientIdAsync(TOpenIdConnectClient application, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<string?>(application.ClientId);
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetClientSecretAsync(TOpenIdConnectClient application, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<string?>(application.ClientSecret);
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetClientTypeAsync(TOpenIdConnectClient application, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<string?>(application.Type.ToString()?.ToLower());
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetConsentTypeAsync(TOpenIdConnectClient application, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<string?>(application.ConsentType.ToString().ToLower());
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetDisplayNameAsync(TOpenIdConnectClient application, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<string?>(application.Name);
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(TOpenIdConnectClient application, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<ImmutableDictionary<CultureInfo, string>>(ImmutableDictionary.Create<CultureInfo, string>());

            //if (string.IsNullOrEmpty(application.DisplayNames))
            //{
            //    return new ValueTask<ImmutableDictionary<CultureInfo, string>>(ImmutableDictionary.Create<CultureInfo, string>());
            //}

            //// Note: parsing the stringified display names is an expensive operation.
            //// To mitigate that, the resulting object is stored in the memory cache.
            //var key = string.Concat("7762c378-c113-4564-b14b-1402b3949aaa", "\x1e", application.DisplayNames);
            //var names = Cache.GetOrCreate(key, entry =>
            //{
            //    entry.SetPriority(CacheItemPriority.High)
            //         .SetSlidingExpiration(TimeSpan.FromMinutes(1));

            //    using var document = JsonDocument.Parse(application.DisplayNames);
            //    var builder = ImmutableDictionary.CreateBuilder<CultureInfo, string>();

            //    foreach (var property in document.RootElement.EnumerateObject())
            //    {
            //        var value = property.Value.GetString();
            //        if (string.IsNullOrEmpty(value))
            //        {
            //            continue;
            //        }

            //        builder[CultureInfo.GetCultureInfo(property.Name)] = value;
            //    }

            //    return builder.ToImmutable();
            //});

            //return new ValueTask<ImmutableDictionary<CultureInfo, string>>(names);
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetIdAsync(TOpenIdConnectClient application, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            return new ValueTask<string?>(application.Id.ToString());
        }

        protected static Dictionary<TAllowedGrantTypeValue?, string[]> AuthorizationCode = new Dictionary<TAllowedGrantTypeValue?, string[]>
        {

            [(TAllowedGrantTypeValue)Enum.ToObject(typeof(TAllowedGrantTypeValue), 1)] = new string[] { OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode },
            [(TAllowedGrantTypeValue)Enum.ToObject(typeof(TAllowedGrantTypeValue), 2)] = new string[] { OpenIddictConstants.Permissions.GrantTypes.Implicit },
            [(TAllowedGrantTypeValue)Enum.ToObject(typeof(TAllowedGrantTypeValue), 3)] = new string[] { OpenIddictConstants.Permissions.GrantTypes.Password },
            [(TAllowedGrantTypeValue)Enum.ToObject(typeof(TAllowedGrantTypeValue), 4)] = new string[] { OpenIddictConstants.Permissions.Endpoints.Token, OpenIddictConstants.Permissions.GrantTypes.ClientCredentials },
            [(TAllowedGrantTypeValue)Enum.ToObject(typeof(TAllowedGrantTypeValue), 6)] = new string[] { OpenIddictConstants.Permissions.GrantTypes.DeviceCode },
            [(TAllowedGrantTypeValue)Enum.ToObject(typeof(TAllowedGrantTypeValue), 7)] = new string[] { OpenIddictConstants.Permissions.GrantTypes.RefreshToken },



        };

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableArray<string>> GetPermissionsAsync(TOpenIdConnectClient application, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            var permissions = application.AllowedGrantTypes.SelectMany(g =>
                AuthorizationCode.ContainsKey(g.AllowedGrantTypeValue) ?
                AuthorizationCode[g.AllowedGrantTypeValue] : new string[] { OpenIddictConstants.Permissions.Prefixes.GrantType + g.AllowedGrantTypeValue.ToString()?.ToLower() });


            return new ValueTask<ImmutableArray<string>>(permissions.ToImmutableArray());

            //if (string.IsNullOrEmpty(application.Permissions))
            //{
            //    return new ValueTask<ImmutableArray<string>>(ImmutableArray.Create<string>());
            //}

            //// Note: parsing the stringified permissions is an expensive operation.
            //// To mitigate that, the resulting array is stored in the memory cache.
            //var key = string.Concat("0347e0aa-3a26-410a-97e8-a83bdeb21a1f", "\x1e", application.Permissions);
            //var permissions = Cache.GetOrCreate(key, entry =>
            //{
            //    entry.SetPriority(CacheItemPriority.High)
            //         .SetSlidingExpiration(TimeSpan.FromMinutes(1));

            //    using var document = JsonDocument.Parse(application.Permissions);
            //    var builder = ImmutableArray.CreateBuilder<string>(document.RootElement.GetArrayLength());

            //    foreach (var element in document.RootElement.EnumerateArray())
            //    {
            //        var value = element.GetString();
            //        if (string.IsNullOrEmpty(value))
            //        {
            //            continue;
            //        }

            //        builder.Add(value);
            //    }

            //    return builder.ToImmutable();
            //});

            //return new ValueTask<ImmutableArray<string>>(permissions);
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableArray<string>> GetPostLogoutRedirectUrisAsync(TOpenIdConnectClient application, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (string.IsNullOrEmpty(application.PostLogoutRedirectURIs))
            {
                return new ValueTask<ImmutableArray<string>>(ImmutableArray.Create<string>());
            }

            // Note: parsing the stringified addresses is an expensive operation.
            // To mitigate that, the resulting array is stored in the memory cache.
            var key = string.Concat("fb14dfb9-9216-4b77-bfa9-7e85f8201ff4", "\x1e", application.PostLogoutRedirectURIs);
            var addresses = Cache.GetOrCreate(key, entry =>
            {
                entry.SetPriority(CacheItemPriority.High)
                     .SetSlidingExpiration(TimeSpan.FromMinutes(1));

                using var document = JsonDocument.Parse(application.PostLogoutRedirectURIs);
                var builder = ImmutableArray.CreateBuilder<string>(document.RootElement.GetArrayLength());

                foreach (var element in document.RootElement.EnumerateArray())
                {
                    var value = element.GetString();
                    if (string.IsNullOrEmpty(value))
                    {
                        continue;
                    }

                    builder.Add(value);
                }

                return builder.ToImmutable();
            });

            return new ValueTask<ImmutableArray<string>>(addresses);
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TOpenIdConnectClient application, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (string.IsNullOrEmpty(application.Properties))
            {
                return new ValueTask<ImmutableDictionary<string, JsonElement>>(ImmutableDictionary.Create<string, JsonElement>());
            }

            // Note: parsing the stringified properties is an expensive operation.
            // To mitigate that, the resulting object is stored in the memory cache.
            var key = string.Concat("2e3e9680-5654-48d8-a27d-b8bb4f0f1d50", "\x1e", application.Properties);
            var properties = Cache.GetOrCreate(key, entry =>
            {
                entry.SetPriority(CacheItemPriority.High)
                     .SetSlidingExpiration(TimeSpan.FromMinutes(1));

                using var document = JsonDocument.Parse(application.Properties);
                var builder = ImmutableDictionary.CreateBuilder<string, JsonElement>();

                foreach (var property in document.RootElement.EnumerateObject())
                {
                    builder[property.Name] = property.Value.Clone();
                }

                return builder.ToImmutable();
            });

            return new ValueTask<ImmutableDictionary<string, JsonElement>>(properties);
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableArray<string>> GetRedirectUrisAsync(TOpenIdConnectClient application, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (string.IsNullOrEmpty(application.RedirectUris))
            {
                return new ValueTask<ImmutableArray<string>>(ImmutableArray.Create<string>());
            }

            // Note: parsing the stringified addresses is an expensive operation.
            // To mitigate that, the resulting array is stored in the memory cache.
            var key = string.Concat("851d6f08-2ee0-4452-bbe5-ab864611ecaa", "\x1e", application.RedirectUris);
            var addresses = Cache.GetOrCreate(key, entry =>
            {
                entry.SetPriority(CacheItemPriority.High)
                     .SetSlidingExpiration(TimeSpan.FromMinutes(1));

                using var document = JsonDocument.Parse(application.RedirectUris);
                var builder = ImmutableArray.CreateBuilder<string>(document.RootElement.GetArrayLength());

                foreach (var element in document.RootElement.EnumerateArray())
                {
                    var value = element.GetString();
                    if (string.IsNullOrEmpty(value))
                    {
                        continue;
                    }

                    builder.Add(value);
                }

                return builder.ToImmutable();
            });

            return new ValueTask<ImmutableArray<string>>(addresses);
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableArray<string>> GetRequirementsAsync(TOpenIdConnectClient application, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            var requirements = new List<string>();

            if (application.RequirePKCE ?? false)
                requirements.Add(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);


            return new ValueTask<ImmutableArray<string>>(requirements.ToImmutableArray());

            //if (string.IsNullOrEmpty(application.Requirements))
            //{
            //    return new ValueTask<ImmutableArray<string>>(ImmutableArray.Create<string>());
            //}



            //// Note: parsing the stringified requirements is an expensive operation.
            //// To mitigate that, the resulting array is stored in the memory cache.
            //var key = string.Concat("b4808a89-8969-4512-895f-a909c62a8995", "\x1e", application.Requirements);
            //var requirements = Cache.GetOrCreate(key, entry =>
            //{
            //    entry.SetPriority(CacheItemPriority.High)
            //         .SetSlidingExpiration(TimeSpan.FromMinutes(1));

            //    using var document = JsonDocument.Parse(application.Requirements);
            //    var builder = ImmutableArray.CreateBuilder<string>(document.RootElement.GetArrayLength());

            //    foreach (var element in document.RootElement.EnumerateArray())
            //    {
            //        var value = element.GetString();
            //        if (string.IsNullOrEmpty(value))
            //        {
            //            continue;
            //        }

            //        builder.Add(value);
            //    }

            //    return builder.ToImmutable();
            //});

            //return new ValueTask<ImmutableArray<string>>(requirements);
        }

        /// <inheritdoc/>
        public virtual ValueTask<TOpenIdConnectClient> InstantiateAsync(CancellationToken cancellationToken)
        {
            try
            {
                return new ValueTask<TOpenIdConnectClient>(Activator.CreateInstance<TOpenIdConnectClient>());
            }

            catch (MemberAccessException exception)
            {
                return new ValueTask<TOpenIdConnectClient>(Task.FromException<TOpenIdConnectClient>(
                    new InvalidOperationException(SR.GetResourceString(SR.ID0240), exception)));
            }
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectClient> ListAsync(int? count, int? offset, CancellationToken cancellationToken)
        {
            var query = Applications.AsQueryable().OrderBy(application => application.Id!).AsTracking();

            if (offset.HasValue)
            {
                query = query.Skip(offset.Value);
            }

            if (count.HasValue)
            {
                query = query.Take(count.Value);
            }

            return query.AsAsyncEnumerable(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TResult> ListAsync<TState, TResult>(
            Func<IQueryable<TOpenIdConnectClient>, TState, IQueryable<TResult>> query,
            TState state, CancellationToken cancellationToken)
        {
            if (query is null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return query(Loader, state).AsAsyncEnumerable(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual ValueTask SetClientIdAsync(TOpenIdConnectClient application, string? identifier, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            application.ClientId = identifier;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetClientSecretAsync(TOpenIdConnectClient application, string? secret, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            application.ClientSecret = secret;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetClientTypeAsync(TOpenIdConnectClient application, string? type, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (Enum.TryParse(type, out TOpenIdConnectClientTypes typedType))
                application.Type = typedType;


            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetConsentTypeAsync(TOpenIdConnectClient application, string? type, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (Enum.TryParse(type, out TOpenIdConnectClientConsentTypes typedType))
                application.ConsentType = typedType;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetDisplayNameAsync(TOpenIdConnectClient application, string? name, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            application.Name = name;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetDisplayNamesAsync(TOpenIdConnectClient application,
            ImmutableDictionary<CultureInfo, string> names, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            //if (names is null || names.IsEmpty)
            //{
            //    application.DisplayNames = null;

            //    return default;
            //}

            //using var stream = new MemoryStream();
            //using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
            //{
            //    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            //    Indented = false
            //});

            //writer.WriteStartObject();

            //foreach (var pair in names)
            //{
            //    writer.WritePropertyName(pair.Key.Name);
            //    writer.WriteStringValue(pair.Value);
            //}

            //writer.WriteEndObject();
            //writer.Flush();

            //application.DisplayNames = Encoding.UTF8.GetString(stream.ToArray());

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetPermissionsAsync(TOpenIdConnectClient application, ImmutableArray<string> permissions, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            //if (permissions.IsDefaultOrEmpty)
            //{
            //    application.Permissions = null;

            //    return default;
            //}

            //using var stream = new MemoryStream();
            //using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
            //{
            //    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            //    Indented = false
            //});

            //writer.WriteStartArray();

            //foreach (var permission in permissions)
            //{
            //    writer.WriteStringValue(permission);
            //}

            //writer.WriteEndArray();
            //writer.Flush();

            //application.Permissions = Encoding.UTF8.GetString(stream.ToArray());

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetPostLogoutRedirectUrisAsync(TOpenIdConnectClient application,
            ImmutableArray<string> addresses, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (addresses.IsDefaultOrEmpty)
            {
                application.PostLogoutRedirectURIs = null;

                return default;
            }

            using var stream = new MemoryStream();
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                Indented = false
            });

            writer.WriteStartArray();

            foreach (var address in addresses)
            {
                writer.WriteStringValue(address);
            }

            writer.WriteEndArray();
            writer.Flush();

            application.PostLogoutRedirectURIs = Encoding.UTF8.GetString(stream.ToArray());

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetPropertiesAsync(TOpenIdConnectClient application,
            ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (properties is null || properties.IsEmpty)
            {
                application.Properties = null;

                return default;
            }

            using var stream = new MemoryStream();
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                Indented = false
            });

            writer.WriteStartObject();

            foreach (var property in properties)
            {
                writer.WritePropertyName(property.Key);
                property.Value.WriteTo(writer);
            }

            writer.WriteEndObject();
            writer.Flush();

            application.Properties = Encoding.UTF8.GetString(stream.ToArray());

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetRedirectUrisAsync(TOpenIdConnectClient application,
            ImmutableArray<string> addresses, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            if (addresses.IsDefaultOrEmpty)
            {
                application.RedirectUris = null;

                return default;
            }

            using var stream = new MemoryStream();
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                Indented = false
            });

            writer.WriteStartArray();

            foreach (var address in addresses)
            {
                writer.WriteStringValue(address);
            }

            writer.WriteEndArray();
            writer.Flush();

            application.RedirectUris = Encoding.UTF8.GetString(stream.ToArray());

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetRequirementsAsync(TOpenIdConnectClient application, ImmutableArray<string> requirements, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            //if (requirements.IsDefaultOrEmpty)
            //{
            //    application.Requirements = null;

            //    return default;
            //}

            //using var stream = new MemoryStream();
            //using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
            //{
            //    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            //    Indented = false
            //});

            //writer.WriteStartArray();

            //foreach (var requirement in requirements)
            //{
            //    writer.WriteStringValue(requirement);
            //}

            //writer.WriteEndArray();
            //writer.Flush();

            //application.Requirements = Encoding.UTF8.GetString(stream.ToArray());

            return default;
        }

        /// <inheritdoc/>
        public virtual async ValueTask UpdateAsync(TOpenIdConnectClient application, CancellationToken cancellationToken)
        {
            if (application is null)
            {
                throw new ArgumentNullException(nameof(application));
            }

            Context.Attach(application);

            //// Generate a new concurrency token and attach it
            //// to the application before persisting the changes.
            //application.ConcurrencyToken = Guid.NewGuid().ToString();

            Context.Update(application);

            try
            {
                await Context.SaveChangesAsync(await PrincipalService.CreatePrincipalForUpdateClient());
            }

            catch (DbUpdateConcurrencyException exception)
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                Context.ResetEntryTracking(application); // Context.Entry(application).State = EntityState.Unchanged;

                throw new OpenIddictExceptions.ConcurrencyException(SR.GetResourceString(SR.ID0239), exception);
            }
        }




    }


}