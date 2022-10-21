using EAVFramework;
using EAVFramework.Endpoints;
using Microsoft.AspNetCore.Http;
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
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;


namespace EAVFW.Extensions.OIDCIdentity
{

    public class OpenIddictEAVFrameworkTokenStore<TContext, TOpenIdConnectClient, TOpenIdConnectAuthorization, TOpenIdConnectToken,
        TOpenIdConnectTokenStatus, TOpenIdConnectTokenType, TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType, TAllowedGrantType, TOpenIdConnectAuthorizationScope, TOpenIdConnectClientTypes,
        TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue, TOpenIdConnectScope, TOpenIdConnectScopeResource, TOpenIdConnectResource, TOpenIdConnectIdentityResource>
        : OIDConnectStore<TContext, TOpenIdConnectClient, TOpenIdConnectAuthorization, TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType, TOpenIdConnectToken, TOpenIdConnectTokenType,
            TOpenIdConnectTokenStatus, TAllowedGrantType, TOpenIdConnectAuthorizationScope, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes, TAllowedGrantTypeValue
            , TOpenIdConnectScope, TOpenIdConnectScopeResource, TOpenIdConnectResource, TOpenIdConnectIdentityResource>, IOpenIddictTokenStore<TOpenIdConnectToken>
          where TContext : DynamicContext
          where TOpenIdConnectClient : DynamicEntity, IOpenIdConnectClient<TAllowedGrantType, TOpenIdConnectClientTypes, TOpenIdConnectClientConsentTypes>
          where TOpenIdConnectAuthorization : DynamicEntity, IOpenIdConnectAuthorization<TOpenIdConnectClient,  TOpenIdConnectAuthorizationStatus, TOpenIdConnectAuthorizationType>
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


        public OpenIddictEAVFrameworkTokenStore(
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



        private IQueryable<TOpenIdConnectToken> Loader => Tokens.Include(token => token.Client).Include(token => token.Authorization).AsTracking();
        /// <inheritdoc/>
        public virtual async ValueTask<long> CountAsync(CancellationToken cancellationToken)
            => await Tokens.AsQueryable().LongCountAsync(cancellationToken);

        /// <inheritdoc/>
        public virtual async ValueTask<long> CountAsync<TResult>(Func<IQueryable<TOpenIdConnectToken>, IQueryable<TResult>> query, CancellationToken cancellationToken)
        {
            if (query is null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return await query(Tokens).LongCountAsync(cancellationToken);
        }


        /// <inheritdoc/>
        public virtual async ValueTask CreateAsync(TOpenIdConnectToken token, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            Tokens.Add(token);

            //Tokens are created by the clientids. 
            //new ClaimsPrincipal(new ClaimsIdentity(new Claim[] {
            //                       new Claim(Claims.Subject,token.ClientId.ToString())
            //                    }, EAVFramework.Constants.DefaultCookieAuthenticationScheme))
            await Context.SaveChangesAsync(await PrincipalService.CreatePrincipalForToken(token.ClientId.ToString()));
        }

        /// <inheritdoc/>
        public virtual async ValueTask DeleteAsync(TOpenIdConnectToken token, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            Tokens.Remove(token);

            try
            {
                await Context.SaveChangesAsync(await PrincipalService.CreatePrincipalForDeleteToken());
            }

            catch (DbUpdateConcurrencyException exception)
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                Context.Context.Entry(token).State = EntityState.Unchanged;

                throw new OpenIddictExceptions.ConcurrencyException(SR.GetResourceString(SR.ID0247), exception);
            }
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectToken> FindAsync(string subject, string client, CancellationToken cancellationToken)
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
            // filtered using token.Application.Id.Equals(key). To work around this issue,
            // this compiled query uses an explicit join before applying the equality check.
            // See https://github.com/openiddict/openiddict-core/issues/499 for more information.



            return (from token in Loader
                    where token.SubjectId == Guid.Parse(subject) && token.Client.Id == Guid.Parse(client)

                    select token).AsAsyncEnumerable(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectToken> FindAsync(
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



            TOpenIdConnectTokenStatus? statusEnum = Enum.Parse<TOpenIdConnectTokenStatus>(status, true);

            return (from token in Loader
                    where token.SubjectId == Guid.Parse(subject) &&
                          Object.Equals(token.Status, statusEnum) &&
                          token.ClientId == Guid.Parse(client)
                    select token).AsAsyncEnumerable(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectToken> FindAsync(
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

            var statusEnum = Enum.Parse<TOpenIdConnectTokenStatus>(status.Replace("_", ""), true);
            var typeEnum = Enum.Parse<TOpenIdConnectTokenType>(type.Replace("_", ""), true);
            return (from token in Loader
                    where token.SubjectId == Guid.Parse(subject) &&
                         Object.Equals(token.Status, statusEnum) &&
                          token.ClientId == Guid.Parse(client) &&
                         Object.Equals(token.Type, typeEnum)
                    select token).AsAsyncEnumerable(cancellationToken);


        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectToken> FindByApplicationIdAsync(string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
            }

            // Note: due to a bug in Entity Framework Core's query visitor, the tokens can't be
            // filtered using token.Application.Id.Equals(key). To work around this issue,
            // this method is overriden to use an explicit join before applying the equality check.
            // See https://github.com/openiddict/openiddict-core/issues/499 for more information.



            return (from token in Loader

                    where token.ClientId == Guid.Parse(identifier)
                    select token).AsAsyncEnumerable(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectToken> FindByAuthorizationIdAsync(string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
            }

            // Note: due to a bug in Entity Framework Core's query visitor, the tokens can't be
            // filtered using token.Authorization.Id.Equals(key). To work around this issue,
            // this method is overriden to use an explicit join before applying the equality check.
            // See https://github.com/openiddict/openiddict-core/issues/499 for more information.



            return (from token in Loader
                    where token.AuthorizationId == Guid.Parse(identifier)
                    select token).AsAsyncEnumerable(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual async ValueTask<TOpenIdConnectToken?> FindByIdAsync(string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
            }



            return await (from token in Loader
                          where token.Id == Guid.Parse(identifier)
                          select token).FirstOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual async ValueTask<TOpenIdConnectToken?> FindByReferenceIdAsync(string identifier, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(identifier))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0195), nameof(identifier));
            }

            return await (from token in Loader
                          where token.ReferenceId == Guid.Parse(identifier)
                          select token).FirstOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectToken> FindBySubjectAsync(string subject, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(subject))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0198), nameof(subject));
            }

            return (from token in Loader
                    where token.SubjectId == Guid.Parse(subject)
                    select token).AsAsyncEnumerable(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetApplicationIdAsync(TOpenIdConnectToken token, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return new ValueTask<string?>(token.ClientId.ToString());

        }

        /// <inheritdoc/>
        public virtual async ValueTask<TResult?> GetAsync<TState, TResult>(
            Func<IQueryable<TOpenIdConnectToken>, TState, IQueryable<TResult>> query,
            TState state, CancellationToken cancellationToken)
        {
            if (query is null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return await query(Loader, state).FirstOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetAuthorizationIdAsync(TOpenIdConnectToken token, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return new ValueTask<string?>(token.AuthorizationId.ToString());
        }

        /// <inheritdoc/>
        public virtual ValueTask<DateTimeOffset?> GetCreationDateAsync(TOpenIdConnectToken token, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            if (token.CreatedOn is null)
            {
                return new ValueTask<DateTimeOffset?>(result: null);
            }

            return new ValueTask<DateTimeOffset?>(DateTime.SpecifyKind(token.CreatedOn.Value, DateTimeKind.Utc));
        }

        /// <inheritdoc/>
        public virtual ValueTask<DateTimeOffset?> GetExpirationDateAsync(TOpenIdConnectToken token, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            if (token.ExpirationDate is null)
            {
                return new ValueTask<DateTimeOffset?>(result: null);
            }

            return new ValueTask<DateTimeOffset?>(DateTime.SpecifyKind(token.ExpirationDate.Value, DateTimeKind.Utc));
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetIdAsync(TOpenIdConnectToken token, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return new ValueTask<string?>(token.Id.ToString());
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetPayloadAsync(TOpenIdConnectToken token, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return new ValueTask<string?>(token.Payload);
        }

        /// <inheritdoc/>
        public virtual ValueTask<ImmutableDictionary<string, JsonElement>> GetPropertiesAsync(TOpenIdConnectToken token, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            if (string.IsNullOrEmpty(token.Properties))
            {
                return new ValueTask<ImmutableDictionary<string, JsonElement>>(ImmutableDictionary.Create<string, JsonElement>());
            }

            // Note: parsing the stringified properties is an expensive operation.
            // To mitigate that, the resulting object is stored in the memory cache.
            var key = string.Concat("d0509397-1bbf-40e7-97e1-5e6d7bc2536c", "\x1e", token.Properties);
            var properties = Cache.GetOrCreate(key, entry =>
            {
                entry.SetPriority(CacheItemPriority.High)
                     .SetSlidingExpiration(TimeSpan.FromMinutes(1));

                using var document = JsonDocument.Parse(token.Properties);
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
        public virtual ValueTask<DateTimeOffset?> GetRedemptionDateAsync(TOpenIdConnectToken token, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            if (token.RedemptionDate is null)
            {
                return new ValueTask<DateTimeOffset?>(result: null);
            }

            return new ValueTask<DateTimeOffset?>(DateTime.SpecifyKind(token.RedemptionDate.Value, DateTimeKind.Utc));
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetReferenceIdAsync(TOpenIdConnectToken token, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return new ValueTask<string?>(token.ReferenceId.ToString());
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetStatusAsync(TOpenIdConnectToken token, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return new ValueTask<string?>(token.Status.ToString());
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetSubjectAsync(TOpenIdConnectToken token, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return new ValueTask<string?>(token.SubjectId.ToString());
        }

        /// <inheritdoc/>
        public virtual ValueTask<string?> GetTypeAsync(TOpenIdConnectToken token, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return new ValueTask<string?>(token.Type.ToString());
        }

        /// <inheritdoc/>
        public virtual ValueTask<TOpenIdConnectToken> InstantiateAsync(CancellationToken cancellationToken)
        {
            try
            {
                return new ValueTask<TOpenIdConnectToken>(Activator.CreateInstance<TOpenIdConnectToken>());
            }

            catch (MemberAccessException exception)
            {
                return new ValueTask<TOpenIdConnectToken>(Task.FromException<TOpenIdConnectToken>(
                    new InvalidOperationException(SR.GetResourceString(SR.ID0248), exception)));
            }
        }

        /// <inheritdoc/>
        public virtual IAsyncEnumerable<TOpenIdConnectToken> ListAsync(int? count, int? offset, CancellationToken cancellationToken)
        {
            var query = Loader
                              .OrderBy(token => token.Id!)
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
            Func<IQueryable<TOpenIdConnectToken>, TState, IQueryable<TResult>> query,
            TState state, CancellationToken cancellationToken)
        {
            if (query is null)
            {
                throw new ArgumentNullException(nameof(query));
            }

            return query(
               Loader, state).AsAsyncEnumerable(cancellationToken);
        }

        /// <inheritdoc/>
        public virtual async ValueTask PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken)
        {
            // Note: Entity Framework Core doesn't support set-based deletes, which prevents removing
            // entities in a single command without having to retrieve and materialize them first.
            // To work around this limitation, entities are manually listed and deleted using a batch logic.

            List<Exception>? exceptions = null;

            async ValueTask<IDbContextTransaction?> CreateTransactionAsync()
            {
                // Note: transactions that specify an explicit isolation level are only supported by
                // relational providers and trying to use them with a different provider results in
                // an invalid operation exception being thrown at runtime. To prevent that, a manual
                // check is made to ensure the underlying transaction manager is relational.
                var manager = Context.Context.Database.GetService<IDbContextTransactionManager>();
                if (manager is IRelationalTransactionManager)
                {
                    // Note: relational providers like Sqlite are known to lack proper support
                    // for repeatable read transactions. To ensure this method can be safely used
                    // with such providers, the database transaction is created in a try/catch block.
                    try
                    {
                        return await Context.Context.Database.BeginTransactionAsync(IsolationLevel.RepeatableRead, cancellationToken);
                    }

                    catch
                    {
                        return null;
                    }
                }

                return null;
            }

            // Note: to avoid sending too many queries, the maximum number of elements
            // that can be removed by a single call to PruneAsync() is deliberately limited.
            for (var index = 0; index < 1_000; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // To prevent concurrency exceptions from being thrown if an entry is modified
                // after it was retrieved from the database, the following logic is executed in
                // a repeatable read transaction, that will put a lock on the retrieved entries
                // and thus prevent them from being concurrently modified outside this block.
                using var transaction = await CreateTransactionAsync();

                // Note: the Oracle MySQL provider doesn't support DateTimeOffset and is unable
                // to create a SQL query with an expression calling DateTimeOffset.UtcDateTime.
                // To work around this limitation, the threshold represented as a DateTimeOffset
                // instance is manually converted to a UTC DateTime instance outside the query.
                var date = threshold.UtcDateTime;
                var inactive = (TOpenIdConnectAuthorization)Enum.ToObject(typeof(TOpenIdConnectAuthorization), 0);
                var valid = (TOpenIdConnectAuthorization)Enum.ToObject(typeof(TOpenIdConnectAuthorization), 1);
                var authStatusValid = (TOpenIdConnectAuthorizationStatus)Enum.ToObject(typeof(TOpenIdConnectAuthorizationStatus), 1);
                var tokens = await
                    (from token in Tokens.AsTracking()
                     where token.CreatedOn < date
                     where (!Object.Equals(token.Status, inactive) && !Object.Equals(token.Status, valid)) ||
                           (token.Authorization != null && !Object.Equals(token.Authorization.Status, authStatusValid)) ||
                            token.ExpirationDate < DateTime.UtcNow
                     orderby token.Id
                     select token).Take(1_000).ToListAsync(cancellationToken);

                if (tokens.Count == 0)
                {
                    break;
                }

                Context.Context.RemoveRange(tokens);

                try
                {
                    await Context.SaveChangesAsync(await PrincipalService.CreatePrincipalForPruneToken());
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
                throw new AggregateException(SR.GetResourceString(SR.ID0249), exceptions);
            }
        }

        /// <inheritdoc/>
        public virtual async ValueTask SetApplicationIdAsync(TOpenIdConnectToken token, string? identifier, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }
            token.ClientId = identifier == null ? null : Guid.Parse(identifier);
        }

        /// <inheritdoc/>
        public virtual async ValueTask SetAuthorizationIdAsync(TOpenIdConnectToken token, string? identifier, CancellationToken cancellationToken)
        {
            token.AuthorizationId = identifier == null ? null : Guid.Parse(identifier);
        }

        /// <inheritdoc/>
        public virtual ValueTask SetCreationDateAsync(TOpenIdConnectToken token, DateTimeOffset? date, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            token.CreatedOn = date?.UtcDateTime;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetExpirationDateAsync(TOpenIdConnectToken token, DateTimeOffset? date, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            token.ExpirationDate = date?.UtcDateTime;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetPayloadAsync(TOpenIdConnectToken token, string? payload, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            token.Payload = payload;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetPropertiesAsync(TOpenIdConnectToken token,
            ImmutableDictionary<string, JsonElement> properties, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            if (properties is null || properties.IsEmpty)
            {
                token.Properties = null;

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

            token.Properties = Encoding.UTF8.GetString(stream.ToArray());

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetRedemptionDateAsync(TOpenIdConnectToken token, DateTimeOffset? date, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            token.RedemptionDate = date?.UtcDateTime;

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetReferenceIdAsync(TOpenIdConnectToken token, string? identifier, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            token.ReferenceId = identifier == null ? null : Guid.Parse(identifier);

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetStatusAsync(TOpenIdConnectToken token, string? status, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            token.Status = status == null ? null : Enum.Parse<TOpenIdConnectTokenStatus>(status.Replace("_", ""), true);

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetSubjectAsync(TOpenIdConnectToken token, string? subject, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            token.SubjectId = subject == null ? null : Guid.Parse(subject);

            return default;
        }

        /// <inheritdoc/>
        public virtual ValueTask SetTypeAsync(TOpenIdConnectToken token, string? type, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            token.Type = type == null ? null : Enum.Parse<TOpenIdConnectTokenType>(type.Replace("_", ""), true);

            return default;
        }

        /// <inheritdoc/>
        public virtual async ValueTask UpdateAsync(TOpenIdConnectToken token, CancellationToken cancellationToken)
        {
            if (token is null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            Tokens.Attach(token);

            // Generate a new concurrency token and attach it
            // to the token before persisting the changes.
            //token.ConcurrencyToken = Guid.NewGuid().ToString();

            Tokens.Update(token);

            try
            {
                await Context.SaveChangesAsync(await PrincipalService.CreatePrincipalForTokenUpdate());
            }

            catch (DbUpdateConcurrencyException exception)
            {
                // Reset the state of the entity to prevents future calls to SaveChangesAsync() from failing.
                Context.Context.Entry(token).State = EntityState.Unchanged;

                throw new OpenIddictExceptions.ConcurrencyException(SR.GetResourceString(SR.ID0247), exception);
            }
        }



    }


}