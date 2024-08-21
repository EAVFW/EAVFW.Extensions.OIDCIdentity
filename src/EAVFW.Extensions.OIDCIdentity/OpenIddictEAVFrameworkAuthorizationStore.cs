using EAVFramework;
using EAVFramework.Endpoints;
using EAVFramework.Shared;
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
    //public interface IOpenIddictEAVFrameworkAuthorizationStore
    //{

    //}

    //[ConstraintMapping(EntityKey = "OpenId Connect Client", ConstraintName = nameof(TOpenIdConnectClient))]
    //[ConstraintMapping(EntityKey = "OpenId Connect Authorization", ConstraintName = nameof(TOpenIdConnectAuthorization))]
    //[ConstraintMapping(EntityKey = "OpenId Connect Token", ConstraintName = nameof(TOpenIdConnectToken))]
    //[ConstraintMapping(EntityKey = "OpenId Connect Token", AttributeKey ="Status", ConstraintName = nameof(TOpenIdConnectTokenStatus))]
    //[ConstraintMapping(EntityKey = "OpenId Connect Token", AttributeKey = "Type", ConstraintName = nameof(TOpenIdConnectTokenType))]
    //[ConstraintMapping(EntityKey = "OpenId Connect Authorization", AttributeKey = "Status", ConstraintName = nameof(TOpenIdConnectAuthorizationStatus))]
    //[ConstraintMapping(EntityKey = "Allowed Grant Type",  ConstraintName = nameof(TAllowedGrantType))]
    //[ConstraintMapping(EntityKey = "OpenId Connect Authorization Scope",ConstraintName = nameof(TOpenIdConnectAuthorizationScope))]
    //[ConstraintMapping(EntityKey = "OpenId Connect Client", AttributeKey ="Consent Type", ConstraintName = nameof(TOpenIdConnectClientConsentTypes))]
    //[ConstraintMapping(EntityKey = "Allowed Grant Type", AttributeKey = "Allowed Grant Type Value", ConstraintName = nameof(TAllowedGrantTypeValue))]
    //[ConstraintMapping(EntityKey = "OpenId Connect Scope",  ConstraintName = nameof(TOpenIdConnectScope))]
    //[ConstraintMapping(EntityKey = "OpenId Connect Scope Resource", ConstraintName = nameof(TOpenIdConnectScopeResource))]
    //[ConstraintMapping(EntityKey = "OpenId Connect Resource", ConstraintName = nameof(TOpenIdConnectResource))]
    //[ConstraintMapping(EntityKey = "OpenId Connect Client", AttributeKey ="Type", ConstraintName = nameof(TOpenIdConnectClientTypes))]
    //[ConstraintMapping(EntityKey = "OpenId Connect Identity Resource", ConstraintName = nameof(TOpenIdConnectIdentityResource))]
    //[ConstraintMapping(EntityKey = "OpenId Connect Authorization", AttributeKey ="Type", ConstraintName = nameof(TOpenIdConnectAuthorizationType))]

     
    public class OpenIddictEAVFrameworkAuthorizationStore<TContext, TOpenIdConnectClient, TOpenIdConnectAuthorization, TOpenIdConnectToken,
        TOpenIdConnectTokenStatus, TOpenIdConnectTokenType, TOpenIdConnectAuthorizationStatus, TAllowedGrantType, TOpenIdConnectAuthorizationScope, TOpenIdConnectClientTypes,
        TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue, TOpenIdConnectScope, TOpenIdConnectScopeResource, TOpenIdConnectResource, TOpenIdConnectIdentityResource, TOpenIdConnectAuthorizationType>
        : OIDConnectStore<TContext, TOpenIdConnectClient, TOpenIdConnectAuthorization, TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType, TOpenIdConnectToken, TOpenIdConnectTokenType,
            TOpenIdConnectTokenStatus, TAllowedGrantType, TOpenIdConnectAuthorizationScope, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue
            , TOpenIdConnectScope, TOpenIdConnectScopeResource, TOpenIdConnectResource, TOpenIdConnectIdentityResource>, IOpenIddictAuthorizationStore<TOpenIdConnectAuthorization>
          where TContext : DynamicContext
           where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes>
          where TOpenIdConnectAuthorization : DynamicEntity, IOpenIdConnectAuthorization<TOpenIdConnectClient, TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType>
          where TOpenIdConnectToken : DynamicEntity, IOpenIdConnectToken<TOpenIdConnectClient, TOpenIdConnectAuthorization, TOpenIdConnectTokenStatus, TOpenIdConnectTokenType>
          where TOpenIdConnectTokenStatus : struct, IConvertible
          where TOpenIdConnectTokenType : struct, IConvertible
          where TOpenIdConnectAuthorizationStatus : struct, IConvertible
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

    {
        public OpenIddictEAVFrameworkAuthorizationStore(
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



        private IQueryable<TOpenIdConnectAuthorization> Loader => from authorization in Authorizations
                    .Include(authorization => authorization.Client)
                   // .Include(a => a.OpenIdConnectAuthorizationScopes.Select(s => s.Scope))
                                                                      .AsTracking()
                                                                  select authorization;



        /// <inheritdoc/>
        public virtual async ValueTask<long> CountAsync(CancellationToken cancellationToken)
            => await Authorizations.AsQueryable().LongCountAsync(cancellationToken);

        /// <inheritdoc/>
        public virtual async ValueTask<long> CountAsync<TResult>(Func<IQueryable<TOpenIdConnectAuthorization>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            if (query is null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return await query(Authorizations).LongCountAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual async ValueTask CreateAsync(TOpenIdConnectAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization is null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            Context.Context.Add(authorization);

            await Context.SaveChangesAsync(await PrincipalService.CreatePrincipalFor(authorization));
        }

        /// <inheritdoc/>
        public virtual async ValueTask DeleteAsync(TOpenIdConnectAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization is null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }



            // Note: due to a bug in Entity Framework Core's query visitor, the tokens can't be
            // filtered using token.Application.Id.Equals(key). To work around this issue,
            // this local method uses an explicit join before applying the equality check.
            // See https://github.com/openiddict/openiddict-core/issues/499 for more information.

            Task<List<TOpenIdConnectToken>> ListTokensAsync()
                => (from token in Tokens.AsTracking()
                    join element in Authorizations.AsTracking() on token.Authorization!.Id equals element.Id
                    where element.Id!.Equals(authorization.Id)
                    select token).ToListAsync(cancellationToken);

            // To prevent an SQL exception from being thrown if a new associated entity is
            // created after the existing entries have been listed, the following logic is
            // executed in a serializable transaction, that will lock the affected tables.
            using var transaction = await Context.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);

            // Remove all the tokens associated with the authorization.
            var tokens = await ListTokensAsync();
            foreach (var token in tokens)
            {
                Context.Remove(token);
            }

            Context.Remove(authorization);

            try
            {
                await Context.SaveChangesAsync(await PrincipalService.DeletePrincipalFor(authorization));
                transaction?.Commit();
            }

            catch (DbUpdateConcurrencyException exception)
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                Context.ResetEntryTracking(authorization); // Context.Entry(authorization).State = EntityState.Unchanged;
                Context.ResetEntryTracking(tokens);

                //foreach (var token in tokens)
                //{
                //    Context.Entry(token).State = EntityState.Unchanged;
                //}

                throw new OpenIddictExceptions.ConcurrencyException(SR.GetResourceString(SR.ID0241), exception);
            }
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectAuthorization> FindAsync(
            string subject, string client, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
            }

            if (string.IsNullOrEmpty(client))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(client));
            }

            // Note: due to a bug in Entity Framework Core's query visitor, the authorizations can't be
            // filtered using authorization.Application.Id.Equals(key). To work around this issue,
            // this method is overriden to use an explicit join before applying the equality check.
            // See https://github.com/openiddict/openiddict-core/issues/499 for more information.

            //  var key = ConvertIdentifierFromString(client);
            var clientid = Guid.Parse(client);
            var sub = Guid.Parse(subject);
            return (from authorization in Loader
                    where authorization.SubjectId == sub
                    join application in Applications.AsTracking() on authorization.ClientId equals application.Id
                    where application.Id == clientid
                    select authorization).AsAsyncEnumerable(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectAuthorization> FindAsync(
            string subject, string client,
            string status, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
            }

            if (string.IsNullOrEmpty(client))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(client));
            }

            if (string.IsNullOrEmpty(status))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0199), nameof(status));
            }

            // Note: due to a bug in Entity Framework Core's query visitor, the authorizations can't be
            // filtered using authorization.Application.Id.Equals(key). To work around this issue,
            // this method is overriden to use an explicit join before applying the equality check.
            // See https://github.com/openiddict/openiddict-core/issues/499 for more information.

            var clientid = Guid.Parse(client);
            var sub = Guid.Parse(subject);
            var statusEnum = Enum.Parse<TOpenIdConnectAuthorizationStatus>(status.Replace("_", ""), true);

            return (from authorization in Loader
                    where authorization.SubjectId == sub && Object.Equals(authorization.Status, statusEnum)
                    join application in Applications.AsTracking() on authorization.ClientId equals application.Id
                    where application.Id == clientid
                    select authorization).AsAsyncEnumerable(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectAuthorization> FindAsync(
            string subject, string client,
            string status, string type, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
            }

            if (string.IsNullOrEmpty(client))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(client));
            }

            if (string.IsNullOrEmpty(status))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0199), nameof(status));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0200), nameof(type));
            }

            // Note: due to a bug in Entity Framework Core's query visitor, the authorizations can't be
            // filtered using authorization.Application.Id.Equals(key). To work around this issue,
            // this method is overriden to use an explicit join before applying the equality check.
            // See https://github.com/openiddict/openiddict-core/issues/499 for more information.


            var clientid = Guid.Parse(client);
            var sub = Guid.Parse(subject);
            var statusEnum = Enum.Parse<TOpenIdConnectAuthorizationStatus>(status.Replace("_", ""), true);
            var typeEnum = Enum.Parse<TOpenIdConnectAuthorizationType>(type.Replace("_", ""), true);

            return (from authorization in Loader
                    where authorization.SubjectId == sub &&
                          Object.Equals(authorization.Status, statusEnum) &&
                          Object.Equals(authorization.Type, typeEnum)
                    join application in Applications.AsTracking() on authorization.ClientId equals application.Id
                    where application.Id == clientid
                    select authorization).AsAsyncEnumerable(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectAuthorization> FindAsync(
            string subject, string client,
            string status, string type,
            ImmutableArray<string> scopes, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
            }

            if (string.IsNullOrEmpty(client))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0124), nameof(client));
            }

            if (string.IsNullOrEmpty(status))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0199), nameof(status));
            }

            if (string.IsNullOrEmpty(type))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0200), nameof(type));
            }

            return ExecuteAsync(cancellationToken);

            async IAsyncEnumerable<TOpenIdConnectAuthorization> ExecuteAsync([EnumeratorCancellation] CancellationToken cancellationToken)
            {

                var clientid = Guid.Parse(client);
                var sub = Guid.Parse(subject);
                var statusEnum = Enum.Parse<TOpenIdConnectAuthorizationStatus>(status.Replace("_", ""), true);
                var typeEnum = Enum.Parse<TOpenIdConnectAuthorizationType>(type.Replace("_", ""), true);


                var authorizations = (from authorization in Loader
                                      where authorization.SubjectId == sub &&
                                            Object.Equals(authorization.Status, statusEnum) &&
                                           Object.Equals(authorization.Type, typeEnum) &&
                                            authorization.ClientId == clientid
                                      select authorization).AsAsyncEnumerable(cancellationToken);

                await foreach (var authorization in authorizations)
                {
                    if (new HashSet<string>(await GetScopesAsync(authorization, cancellationToken), StringComparer.Ordinal).IsSupersetOf(scopes))
                    {
                        yield return authorization;
                    }
                }
            }
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectAuthorization> FindByApplicationIdAsync(
            string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
            }



            var clientid = Guid.Parse(identifier);


            return (from authorization in Loader
                    where authorization.ClientId == clientid
                    select authorization).AsAsyncEnumerable(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual async ValueTask<TOpenIdConnectAuthorization> FindByIdAsync(string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
            }

            var authoirzationId = Guid.Parse(identifier);

            return await (from authorization in Loader
                          where authorization.Id == authoirzationId
                          select authorization).FirstOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectAuthorization> FindBySubjectAsync(
            string subject, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
            }

            var sub = Guid.Parse(subject);

            return (from authorization in Loader
                    where authorization.SubjectId == sub
                    select authorization).AsAsyncEnumerable(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual ValueTask<string> GetApplicationIdAsync(TOpenIdConnectAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization is null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }
            return new ValueTask<string>(authorization.ClientId?.ToString());

        }

        /// <inheritdoc/>
        public virtual async ValueTask<TResult> GetAsync<TState, TResult>(
            Func<IQueryable<TOpenIdConnectAuthorization>, TState, IQueryable<TResult>> query,
            TState state, CancellationToken cancellationToken)
        {
            if (query is null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return await query(
                from authorization in Loader select authorization, state).FirstOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual ValueTask<DateTimeOffset?> GetCreationDateAsync(TOpenIdConnectAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization is null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            if (authorization.CreatedOn == null)
            {
                return new ValueTask<DateTimeOffset?>(result: null);
            }

            return new ValueTask<DateTimeOffset?>(DateTime.SpecifyKind(authorization.CreatedOn.Value, DateTimeKind.Utc));
        }

        /// <inheritdoc/>
        public virtual ValueTask<string> GetIdAsync(TOpenIdConnectAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization is null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return new ValueTask<string>(authorization.Id.ToString());
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TOpenIdConnectAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization is null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            if (string.IsNullOrEmpty(authorization.Properties))
            {
                return new ValueTask<ImmutableDictionary<string, JsonElement>>(ImmutableDictionary.Create<string, JsonElement>());
            }

            // Note: parsing the stringified properties is an expensive operation.
            // To mitigate that, the resulting object is stored in the memory cache.
            var key = string.Concat("68056e1a-dbcf-412b-9a6a-d791c7dbe726", "\x1e", authorization.Properties);
            var properties = Cache.GetOrCreate(key, entry =>
            {
                entry.SetPriority(CacheItemPriority.High)
                     .SetSlidingExpiration(TimeSpan.FromMinutes(1));

                using var document = JsonDocument.Parse(authorization.Properties);
                var builder = ImmutableDictionary.CreateBuilder<string, JsonElement>();

                foreach (var property in document.RootElement.EnumerateObject())
                {
                    builder[property.Name] = property.Value.Clone();
                }

                return builder.ToImmutable();
            });

            return new ValueTask<ImmutableDictionary<string, JsonElement>>(properties);
        }

        private async ValueTask< IEnumerable<TOpenIdConnectAuthorizationScope>> LoadScopes(TOpenIdConnectAuthorization authorization)
        {
            var entry = Context.Entry(authorization);
            var nav = entry.Collection("openidconnectauthorizationscopes");
            await nav.LoadAsync();

            return nav.CurrentValue.OfType<TOpenIdConnectAuthorizationScope>();
        }
        /// <inheritdoc/>
        public virtual async ValueTask<ImmutableArray<string>> GetScopesAsync(TOpenIdConnectAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization is null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

           

            var scopes = await LoadScopes(authorization);
            return  scopes.Select(c => c.Scope.Name).ToImmutableArray();

        }

        /// <inheritdoc/>
        public virtual ValueTask<string> GetStatusAsync(TOpenIdConnectAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization is null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return new ValueTask<string>(authorization.Status?.ToString().ToLower());
        }

        /// <inheritdoc/>
        public virtual ValueTask<string> GetSubjectAsync(TOpenIdConnectAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization is null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return new ValueTask<string>(authorization.SubjectId.ToString());
        }

        /// <inheritdoc/>
        public virtual ValueTask<string> GetTypeAsync(TOpenIdConnectAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization is null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            return new ValueTask<string>(authorization.Type?.ToString().ToLower());
        }

        /// <inheritdoc/>
        public virtual ValueTask<TOpenIdConnectAuthorization> InstantiateAsync(CancellationToken cancellationToken)
        {
            try
            {
                return new ValueTask<TOpenIdConnectAuthorization>(Activator.CreateInstance<TOpenIdConnectAuthorization>());
            }

            catch (MemberAccessException exception)
            {
                return new ValueTask<TOpenIdConnectAuthorization>(Task.FromException<TOpenIdConnectAuthorization>(
                    new InvalidOperationException(SR.GetResourceString(SR.ID0242), exception)));
            }
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectAuthorization> ListAsync(int? count, int? offset, CancellationToken cancellationToken)
        {
            var query = Loader
                                      .OrderBy(authorization => authorization.Id!)
                                      .AsTracking();

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
            Func<IQueryable<TOpenIdConnectAuthorization>, TState, IQueryable<TResult>> query,
            TState state, CancellationToken cancellationToken)
        {
            if (query is null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return query(
                Loader, state).AsAsyncEnumerable(cancellationToken);
        }
        protected static TOpenIdConnectAuthorizationStatus ValidTOpenIdConnectAuthorizationStatus = (TOpenIdConnectAuthorizationStatus)Enum.ToObject(typeof(TOpenIdConnectAuthorizationStatus), 1);
        protected static TOpenIdConnectAuthorizationType AdHocOpenIdConnectAuthorizationType = (TOpenIdConnectAuthorizationType)Enum.ToObject(typeof(TOpenIdConnectAuthorizationType), 1);

        /// <inheritdoc/>
        public virtual async ValueTask PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken)
        {
            // Note: Entity Framework Core doesn't support set-based deletes, which prevents removing
            // entities in a single command without having to retrieve and materialize them first.
            // To work around this limitation, entities are manually listed and deleted using a batch logic.

            List<Exception> exceptions = null;



            // Note: to avoid sending too many queries, the maximum number of elements
            // that can be removed by a single call to PruneAsync() is deliberately limited.
            for (var index = 0; index < 1_000; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // To prevent concurrency exceptions from being thrown if an entry is modified
                // after it was retrieved from the database, the following logic is executed in
                // a repeatable read transaction, that will put a lock on the retrieved entries
                // and thus prevent them from being concurrently modified outside this block.
                using var transaction = await Context.BeginTransactionAsync(IsolationLevel.RepeatableRead, cancellationToken);

                // Note: the Oracle MySQL provider doesn't support DateTimeOffset and is unable
                // to create a SQL query with an expression calling DateTimeOffset.UtcDateTime.
                // To work around this limitation, the threshold represented as a DateTimeOffset
                // instance is manually converted to a UTC DateTime instance outside the query.
                var date = threshold.UtcDateTime;

                var authorizations =
                    await (from authorization in Loader
                           where authorization.CreatedOn < date
                           where !Object.Equals(authorization.Status, ValidTOpenIdConnectAuthorizationStatus) ||
                                (Object.Equals(authorization.Type, AdHocOpenIdConnectAuthorizationType) &&  !Tokens.Any(t=>t.AuthorizationId == authorization.Id))
                           orderby authorization.Id
                           select authorization).Take(1_000).ToListAsync(cancellationToken);

                if (authorizations.Count == 0)
                {
                    break;
                }

                // Note: new tokens may be attached after the authorizations were retrieved
                // from the database since the transaction level is deliberately limited to
                // repeatable read instead of serializable for performance reasons). In this
                // case, the operation will fail, which is considered an acceptable risk.
                Context.Context.RemoveRange(authorizations);

                try
                {
                    await Context.SaveChangesAsync(await PrincipalService.CreatePrincipalForPruneAuthorization());
                    transaction?.Commit();
                }

                catch (Exception exception)
                {
                    exceptions ??= new List<Exception>(capacity: 1);
                    exceptions.Add(exception);
                }
            }

            if (exceptions is not null)
            {
                throw new AggregateException(SR.GetResourceString(SR.ID0243), exceptions);
            }
        }

        /// <inheritdoc/>
        public virtual async ValueTask SetApplicationIdAsync(TOpenIdConnectAuthorization authorization,
            string identifier, CancellationToken cancellationToken)
        {
            if (authorization is null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            if (!string.IsNullOrEmpty(identifier))
            {
                var key = Guid.Parse(identifier);

                // Warning: FindAsync() is deliberately not used to work around a breaking change introduced
                // in Entity Framework Core 3.x (where a ValueTask instead of a Task is now returned).
                var application =
                    await Applications.AsQueryable()
                                      .AsTracking()
                                      .FirstOrDefaultAsync(application => application.Id == key, cancellationToken);

                if (application is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0244));
                }

                authorization.Client = application;
            }

            else
            {
                // If the application is not attached to the authorization, try to load it manually.
                if (authorization.Client is null)
                {
                    var reference = Context.Context.Entry(authorization).Reference(entry => entry.Client);
                    if (reference.EntityEntry.State == EntityState.Detached)
                    {
                        return;
                    }

                    await reference.LoadAsync(cancellationToken);
                }

                authorization.Client = null;
            }
        }

        /// <inheritdoc/>
        public virtual ValueTask SetCreationDateAsync(TOpenIdConnectAuthorization authorization,
            DateTimeOffset? date, CancellationToken cancellationToken)
        {
            if (authorization is null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            authorization.CreatedOn = date?.UtcDateTime;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetPropertiesAsync(TOpenIdConnectAuthorization authorization,
            ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
        {
            if (authorization is null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            if (properties is null || properties.IsEmpty)
            {
                authorization.Properties = null;

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

            authorization.Properties = Encoding.UTF8.GetString(stream.ToArray());

            return default;
        }

        /// <inheritdoc/>
        public virtual async ValueTask SetScopesAsync(TOpenIdConnectAuthorization authorization,
            ImmutableArray<string> scopes, CancellationToken cancellationToken)
        {
            if (authorization is null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            var authorizationscopes = await LoadScopes(authorization);

            foreach (var scope in authorizationscopes.Select(c => c.Scope).Where(sc => !scopes.Contains(sc.Name)))
                Context.Context.Entry(scope).State = EntityState.Deleted;

            var missing = scopes.Where(sc => !authorizationscopes.Any(c => c.Scope.Name == sc)).ToArray();
            var missingIds = await Context.Set<TOpenIdConnectIdentityResource>().Where(c => missing.Contains(c.Name)).Select(c => c.Id).ToListAsync();
            foreach (var scope in missingIds)
                Context.Set<TOpenIdConnectAuthorizationScope>().Add(new TOpenIdConnectAuthorizationScope { ScopeId = scope, AuthorizationId = authorization.Id   });
            
            

        }

        /// <inheritdoc/>
        public virtual ValueTask SetStatusAsync(TOpenIdConnectAuthorization authorization,
            string status, CancellationToken cancellationToken)
        {
            if (authorization is null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            authorization.Status = status == null ? null : Enum.Parse<TOpenIdConnectAuthorizationStatus>(status.Replace("_", ""), true);

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetSubjectAsync(TOpenIdConnectAuthorization authorization,
            string subject, CancellationToken cancellationToken)
        {
            if (authorization is null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            authorization.SubjectId = Guid.Parse(subject!);

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetTypeAsync(TOpenIdConnectAuthorization authorization,
            string type, CancellationToken cancellationToken)
        {
            if (authorization is null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            var typeEnum = Enum.Parse<TOpenIdConnectAuthorizationType>(type, true);
            authorization.Type = typeEnum;

            return default;
        }

        /// <inheritdoc/>
        public virtual async ValueTask UpdateAsync(TOpenIdConnectAuthorization authorization, CancellationToken cancellationToken)
        {
            if (authorization is null)
            {
                throw new ArgumentNullException(nameof(authorization));
            }

            Context.Attach(authorization);

            // Generate a new concurrency token and attach it
            // to the authorization before persisting the changes.
            // authorization.ConcurrencyToken = Guid.NewGuid().ToString();

            Context.Update(authorization);

            try
            {
                await Context.SaveChangesAsync(await PrincipalService.UpdatePrincipalFor(authorization));
            }

            catch (DbUpdateConcurrencyException exception)
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                Context.Context.Entry(authorization).State = EntityState.Unchanged;

                throw new OpenIddictExceptions.ConcurrencyException(SR.GetResourceString(SR.ID0241), exception);
            }
        }

    }


}