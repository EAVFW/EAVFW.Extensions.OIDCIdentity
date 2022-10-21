using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;



namespace EAVFW.Extensions.OIDCIdentity
{
    public static class IEnumerableExtensions
    {

        public static Task<List<T>> ToListAsync<T>(this IAsyncEnumerable<T> source)
        {
            if (source == null)
            {
                throw new ArgumentNullException(nameof(source));
            }

            return ExecuteAsync();

            async Task<List<T>> ExecuteAsync()
            {
                var list = new List<T>();

                await foreach (var element in source)
                {
                    list.Add(element);
                }

                return list;
            }
        }

        /// <summary>
        /// Executes the query and returns the results as a streamed async enumeration.
        /// </summary>
        /// <typeparam name="T">The type of the returned entities.</typeparam>
        /// <param name="source">The query source.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
        /// <returns>The non-streamed async enumeration containing the results.</returns>

        internal static IAsyncEnumerable<T> AsAsyncEnumerable<T>(this IQueryable<T> source, CancellationToken cancellationToken)
        {
            if (source is null)
            {
                throw new ArgumentNullException(nameof(source));
            }

            return ExecuteAsync(source, cancellationToken);

            static async IAsyncEnumerable<T> ExecuteAsync(IQueryable<T> source, [EnumeratorCancellation] CancellationToken cancellationToken)
            {
 
                await foreach (var element in source.AsAsyncEnumerable().WithCancellation(cancellationToken))
                {
                    yield return element;
                }
 
            }
        }
    }

     
}