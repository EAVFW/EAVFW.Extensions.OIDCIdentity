using EAVFramework;
using EAVFramework.Endpoints;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
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
    public class OpenIddictEAVFrameowrkScopeStore<
        TContext,
        TOpenIdConnectScope,
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
        TOpenIdConnectScopeResource,
        TOpenIdConnectResource, TOpenIdConnectIdentityResource
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
        IOpenIddictScopeStore<TOpenIdConnectScope>

        where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes>
        where TOpenIdConnectAuthorization : DynamicEntity, IOpenIdConnectAuthorization<TOpenIdConnectClient,  TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType>
        where TOpenIdConnectAuthorizationStatus : struct, IConvertible
        where TOpenIdConnectToken : DynamicEntity, IOpenIdConnectToken<TOpenIdConnectClient, TOpenIdConnectAuthorization, TOpenIdConnectTokenStatus, TOpenIdConnectTokenType>
        where TOpenIdConnectTokenStatus : struct, IConvertible
        where TOpenIdConnectTokenType : struct, IConvertible
        where TAllowedGrantType : DynamicEntity, IAllowedGrantType<TAllowedGrantTypeValue>
        where TOpenIdConnectAuthorizationScope : DynamicEntity, IOpenIdConnectAuthorizationScope<TOpenIdConnectIdentityResource>, new()
        where TOpenIdConnectClientTypes : struct, IConvertible
        where TOpenIdConnectClientConsentTypes : struct, IConvertible
        where TAllowedGrantTypeValue : struct, IConvertible
            where TOpenIdConnectScopeResource : DynamicEntity, IOpenIdConnectScopeResource<TOpenIdConnectResource, TOpenIdConnectIdentityResource>, new()
            where TOpenIdConnectResource : DynamicEntity, IOpenIdConnectResource
            where TOpenIdConnectScope : DynamicEntity, IOpenIdConnectScope<TOpenIdConnectScopeResource>
        where TOpenIdConnectIdentityResource : DynamicEntity, IOpenIdConnectIdentityResource
         where TOpenIdConnectAuthorizationType : struct, IConvertible
        where TContext : DynamicContext
    {
        public OpenIddictEAVFrameowrkScopeStore(
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
            > principalService,
            EAVDBContext<TContext> context,
            IOptionsMonitor<OpenIddictEAVFrameworkOptions> options) : base(cache, principalService, context, options)
        {

        }



        private IQueryable<TOpenIdConnectScope> Loader => Scopes.Include(x => x.OpenIdConnectScopeResources).ThenInclude(resource => resource.Resource).AsTracking();

        /// <inheritdoc/>
        public virtual async ValueTask<long> CountAsync(CancellationToken cancellationToken)
            => await Scopes.AsQueryable().LongCountAsync(cancellationToken);

        /// <inheritdoc/>
        public virtual async ValueTask<long> CountAsync<TResult>(Func<IQueryable<TOpenIdConnectScope>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            if (query is null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return await query(Scopes).LongCountAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual async ValueTask CreateAsync(TOpenIdConnectScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            Scopes.Add(scope);

            await Context.SaveChangesAsync(await PrincipalService.CreatePrincipalForScope(scope));
        }

        /// <inheritdoc/>
        public virtual async ValueTask DeleteAsync(TOpenIdConnectScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            Context.Remove(scope);

            try
            {
                await Context.SaveChangesAsync(await PrincipalService.CreatePrincipalForDeleteScope(scope));
            }

            catch (DbUpdateConcurrencyException exception)
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                Context.ResetEntryTracking(scope); //Context.Entry(scope).State = EntityState.Unchanged;

                throw new OpenIddictExceptions.ConcurrencyException(SR.GetResourceString(SR.ID0245), exception);
            }
        }

        /// <inheritdoc/>
        public virtual async ValueTask<TOpenIdConnectScope?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
            }


            return await (from scope in Loader
                          where scope.Id == Guid.Parse(identifier)
                          select scope).FirstOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual async ValueTask<TOpenIdConnectScope?> FindByNameAsync(string name, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0202), nameof(name));
            }

            return await (from scope in Loader
                          where scope.Name == name
                          select scope).FirstOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectScope> FindByNamesAsync(
            ImmutableArray<string> names, CancellationToken cancellationToken)
        {
            if (names.Any(name => string.IsNullOrEmpty(name)))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0203), nameof(names));
            }

            // Note: Enumerable.Contains() is deliberately used without the extension method syntax to ensure
            // ImmutableArray.Contains() (which is not fully supported by Entity Framework Core) is not used instead.
            return (from scope in Loader
                    where Enumerable.Contains(names, scope.Name)
                    select scope).AsAsyncEnumerable(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectScope> FindByResourceAsync(
            string resource, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(resource))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0062), nameof(resource));
            }

            // To optimize the efficiency of the query a bit, only scopes whose stringified
            // Resources column contains the specified resource are returned. Once the scopes
            // are retrieved, a second pass is made to ensure only valid elements are returned.
            // Implementers that use this method in a hot path may want to override this method
            // to use SQL Server 2016 functions like JSON_VALUE to make the query more efficient.

            return ExecuteAsync(cancellationToken);

            IAsyncEnumerable<TOpenIdConnectScope> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {
                var scopes = (from scope in Loader
                              where scope.OpenIdConnectScopeResources.Any(s => s.Resource.Name == resource)
                              select scope).AsAsyncEnumerable(cancellationToken);
                return scopes;
                //await foreach (var scope in scopes)
                //{
                //    var resources = await GetResourcesAsync(scope, cancellationToken);
                //    if (resources.Contains(resource, StringComparer.Ordinal))
                //    {
                //        yield return scope;
                //    }
                //}
            }
        }

        /// <inheritdoc/>
        public virtual async ValueTask<TResult> GetAsync<TState, TResult>(
            Func<IQueryable<TOpenIdConnectScope>, TState, IQueryable<TResult>> query,
            TState state, CancellationToken cancellationToken)
        {
            if (query is null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return await query(Scopes.AsTracking(), state).FirstOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetDescriptionAsync(TOpenIdConnectScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return new ValueTask<string?>(scope.Description);
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableDictionary<CultureInfo, string>> GetDescriptionsAsync(TOpenIdConnectScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return new ValueTask<ImmutableDictionary<CultureInfo, string>>(ImmutableDictionary.Create<CultureInfo, string>());
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetDisplayNameAsync(TOpenIdConnectScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return new ValueTask<string?>(scope.DisplayName);
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableDictionary<CultureInfo, string>> GetDisplayNamesAsync(TOpenIdConnectScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }
            return new ValueTask<ImmutableDictionary<CultureInfo, string>>(ImmutableDictionary.Create<CultureInfo, string>());
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetIdAsync(TOpenIdConnectScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return new ValueTask<string?>(scope.Id.ToString());
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetNameAsync(TOpenIdConnectScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return new ValueTask<string?>(scope.Name);
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TOpenIdConnectScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            if (string.IsNullOrEmpty(scope.Properties))
            {
                return new ValueTask<ImmutableDictionary<string, JsonElement>>(ImmutableDictionary.Create<string, JsonElement>());
            }

            // Note: parsing the stringified properties is an expensive operation.
            // To mitigate that, the resulting object is stored in the memory cache.
            var key = string.Concat("78d8dfdd-3870-442e-b62e-dc9bf6eaeff7", "\x1e", scope.Properties);
            var properties = Cache.GetOrCreate(key, entry =>
            {
                entry.SetPriority(CacheItemPriority.High)
                     .SetSlidingExpiration(TimeSpan.FromMinutes(1));

                using var document = JsonDocument.Parse(scope.Properties);
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
        public virtual ValueTask<ImmutableArray<string>> GetResourcesAsync(TOpenIdConnectScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            return new ValueTask<ImmutableArray<string>>(scope.OpenIdConnectScopeResources.Select(c => c.Resource.Name).ToImmutableArray());
        }

        /// <inheritdoc/>
        public virtual ValueTask<TOpenIdConnectScope> InstantiateAsync(CancellationToken cancellationToken)
        {
            try
            {
                return new ValueTask<TOpenIdConnectScope>(Activator.CreateInstance<TOpenIdConnectScope>());
            }

            catch (MemberAccessException exception)
            {
                return new ValueTask<TOpenIdConnectScope>(Task.FromException<TOpenIdConnectScope>(
                    new InvalidOperationException(SR.GetResourceString(SR.ID0246), exception)));
            }
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectScope> ListAsync(int? count, int? offset, CancellationToken cancellationToken)
        {
            var query = Scopes.AsQueryable().OrderBy(scope => scope.Id!).AsTracking();

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
            Func<IQueryable<TOpenIdConnectScope>, TState, IQueryable<TResult>> query,
            TState state, CancellationToken cancellationToken)
        {
            if (query is null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return query(Scopes.AsTracking(), state).AsAsyncEnumerable(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual ValueTask SetDescriptionAsync(TOpenIdConnectScope scope, string? description, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            scope.Description = description;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetDescriptionsAsync(TOpenIdConnectScope scope,
            ImmutableDictionary<CultureInfo, string> descriptions, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }



            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetDisplayNameAsync(TOpenIdConnectScope scope, string? name, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            scope.DisplayName = name;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetDisplayNamesAsync(TOpenIdConnectScope scope,
            ImmutableDictionary<CultureInfo, string> names, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }



            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetNameAsync(TOpenIdConnectScope scope, string? name, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            scope.Name = name;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetPropertiesAsync(TOpenIdConnectScope scope,
            ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            if (properties is null || properties.IsEmpty)
            {
                scope.Properties = null;

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

            scope.Properties = Encoding.UTF8.GetString(stream.ToArray());

            return default;
        }

        /// <inheritdoc/>
        public virtual async ValueTask SetResourcesAsync(TOpenIdConnectScope scope, ImmutableArray<string> resources, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            foreach (var scp in scope.OpenIdConnectScopeResources.Select(c => c.Resource).Where(sc => !resources.Contains(sc.Name)))
                Context.Context.Entry(scp).State = EntityState.Deleted;

            var missing = resources.Where(sc => !scope.OpenIdConnectScopeResources.Any(c => c.Scope.Name == sc)).ToArray();
            var missingIds = await Context.Set<TOpenIdConnectResource>().Where(c => missing.Contains(c.Name)).ToListAsync();
            foreach (var resource in missingIds)
                scope.OpenIdConnectScopeResources.Add(new TOpenIdConnectScopeResource { Resource = resource });

        }

        /// <inheritdoc/>
        public virtual async ValueTask UpdateAsync(TOpenIdConnectScope scope, CancellationToken cancellationToken)
        {
            if (scope is null)
            {
                throw new ArgumentNullException(nameof(scope));
            }

            Context.Attach(scope);

            // Generate a new concurrency token and attach it
            // to the scope before persisting the changes.
            // scope.ConcurrencyToken = Guid.NewGuid().ToString();

            Context.Update(scope);

            try
            {
                await Context.SaveChangesAsync(await PrincipalService.UpdatePrincipalFor(scope));
            }

            catch (DbUpdateConcurrencyException exception)
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                Context.ResetEntryTracking(scope);  //  Context.Entry(scope).State = EntityState.Unchanged;

                throw new OpenIddictExceptions.ConcurrencyException(SR.GetResourceString(SR.ID0245), exception);
            }
        }


    }


}