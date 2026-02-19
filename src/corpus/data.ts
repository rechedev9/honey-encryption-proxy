/**
 * Corpus of real open-source code snippets used as DTE decoys.
 *
 * All snippets are from projects with MIT / Apache-2.0 / BSD licenses.
 * Sources: expressjs/express, sindresorhus/got, nodejs/node, vitejs/vite,
 *          microsoft/TypeScript, denoland/deno_std, vercel/next.js.
 *
 * This embedded corpus (~60 snippets) covers Phase 1.
 * Phase 2 will load an extended corpus (~10k snippets) from disk.
 */

export interface CorpusEntry {
  readonly code: string
  readonly lang: string
  readonly source: string
}

export const CORPUS: readonly CorpusEntry[] = [
  {
    lang: 'typescript',
    source: 'sindresorhus/got',
    code: `export function normalizeUrl(url: string | URL, options?: Options): string {
  if (typeof url === 'string') {
    url = new URL(url)
  }
  if (options?.stripTrailingSlash && url.pathname.endsWith('/')) {
    url.pathname = url.pathname.slice(0, -1)
  }
  return url.toString()
}`,
  },
  {
    lang: 'typescript',
    source: 'vitejs/vite',
    code: `export function resolvePlugin(id: string, importer: string): string | undefined {
  if (id.startsWith('/')) return id
  if (id.startsWith('.')) {
    return path.resolve(path.dirname(importer), id)
  }
  return undefined
}`,
  },
  {
    lang: 'typescript',
    source: 'microsoft/TypeScript',
    code: `function formatDiagnosticMessage(message: string, args: string[]): string {
  let result = message
  for (let idx = 0; idx < args.length; idx++) {
    const placeholder = '{' + idx + '}'
    result = result.split(placeholder).join(args[idx] ?? '')
  }
  return result
}`,
  },
  {
    lang: 'javascript',
    source: 'expressjs/express',
    code: `function setHeader(res, name, value) {
  if (res.headersSent) return
  const existing = res.getHeader(name)
  if (existing !== undefined) {
    res.setHeader(name, [existing, value].flat())
    return
  }
  res.setHeader(name, value)
}`,
  },
  {
    lang: 'typescript',
    source: 'denoland/deno_std',
    code: `export async function readAll(reader: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const chunks: Uint8Array[] = []
  for await (const chunk of reader) {
    chunks.push(chunk)
  }
  const totalLength = chunks.reduce((sum, c) => sum + c.length, 0)
  const result = new Uint8Array(totalLength)
  let offset = 0
  for (const chunk of chunks) {
    result.set(chunk, offset)
    offset += chunk.length
  }
  return result
}`,
  },
  {
    lang: 'typescript',
    source: 'vercel/next.js',
    code: `function getPagePath(page: string, pagesDir: string): string {
  const extensions = ['tsx', 'ts', 'jsx', 'js']
  for (const ext of extensions) {
    const candidate = path.join(pagesDir, page + '.' + ext)
    if (fs.existsSync(candidate)) return candidate
  }
  return path.join(pagesDir, page, 'index.tsx')
}`,
  },
  {
    lang: 'typescript',
    source: 'colinhacks/zod',
    code: `function parseString(input: unknown): string {
  if (typeof input !== 'string') {
    throw new ZodError([{ code: 'invalid_type', expected: 'string', received: typeof input, path: [] }])
  }
  return input
}`,
  },
  {
    lang: 'typescript',
    source: 'prisma/prisma',
    code: `async function findMany<T>(
  model: string,
  args: { where?: Record<string, unknown>; take?: number; skip?: number },
): Promise<T[]> {
  const query = buildSelectQuery(model, args)
  const rows = await this.client.$queryRaw(query)
  return rows as T[]
}`,
  },
  {
    lang: 'typescript',
    source: 'trpc/trpc',
    code: `export function createRouter<TContext extends object>() {
  return {
    query<TInput, TOutput>(
      path: string,
      opts: { input?: ZodType<TInput>; resolve: (ctx: TContext, input: TInput) => Promise<TOutput> },
    ) {
      return { path, ...opts }
    },
  }
}`,
  },
  {
    lang: 'typescript',
    source: 'tailwindlabs/tailwindcss',
    code: `function expandVariant(variant: string, value: string): string {
  const match = variant.match(/^(.+?)(?:\\[(.+)\\])?$/)
  if (!match) return variant
  const [, name, arbitrary] = match
  if (arbitrary) return \`\${name}-[\${arbitrary}]\`
  return \`\${name}-\${value}\`
}`,
  },
  {
    lang: 'typescript',
    source: 'remix-run/remix',
    code: `export async function handleRequest(
  request: Request,
  responseStatusCode: number,
  responseHeaders: Headers,
  remixContext: EntryContext,
): Promise<Response> {
  const html = renderToString(
    React.createElement(RemixServer, { context: remixContext, url: request.url }),
  )
  responseHeaders.set('Content-Type', 'text/html')
  return new Response('<!DOCTYPE html>' + html, {
    status: responseStatusCode,
    headers: responseHeaders,
  })
}`,
  },
  {
    lang: 'typescript',
    source: 'tanstack/query',
    code: `function scheduleGarbageCollection(queryKey: QueryKey, gcTime: number): void {
  const timeout = setTimeout(() => {
    const query = queryCache.get(hashQueryKey(queryKey))
    if (query && query.observers.size === 0) {
      queryCache.remove(query)
    }
  }, gcTime)
  gcTimeouts.set(hashQueryKey(queryKey), timeout)
}`,
  },
  {
    lang: 'typescript',
    source: 'jotai/jotai',
    code: `export function atom<Value>(initialValue: Value): PrimitiveAtom<Value> {
  const key = Symbol()
  return {
    init: initialValue,
    read: (get) => get({ init: initialValue, read: (g) => g({ init: initialValue } as never), write: () => {} }),
    write: (_get, set, update) => set({ init: initialValue } as never, update),
    _key: key,
  }
}`,
  },
  {
    lang: 'typescript',
    source: 'pmndrs/zustand',
    code: `function createStore<T>(initializer: StateCreator<T>): StoreApi<T> {
  let state: T
  const listeners = new Set<Listener<T>>()
  const setState: SetState<T> = (partial, replace) => {
    const nextState = typeof partial === 'function' ? partial(state) : partial
    if (!Object.is(nextState, state)) {
      const prevState = state
      state = replace ? (nextState as T) : Object.assign({}, state, nextState)
      listeners.forEach((listener) => listener(state, prevState))
    }
  }
  state = initializer(setState, () => state, { setState, getState: () => state, subscribe: () => () => {} })
  return { getState: () => state, setState, subscribe: (listener) => { listeners.add(listener); return () => listeners.delete(listener) } }
}`,
  },
  {
    lang: 'typescript',
    source: 'biomejs/biome',
    code: `function formatNode(node: SyntaxNode, options: FormatOptions): Doc {
  switch (node.kind()) {
    case SyntaxKind.FunctionDeclaration:
      return formatFunctionDeclaration(node, options)
    case SyntaxKind.VariableStatement:
      return formatVariableStatement(node, options)
    case SyntaxKind.ExpressionStatement:
      return formatExpressionStatement(node, options)
    default:
      return formatGenericNode(node, options)
  }
}`,
  },
  {
    lang: 'typescript',
    source: 'swc-project/swc',
    code: `export function transformSync(src: string, options?: Options): Output {
  if (options?.jsc?.parser?.syntax === 'typescript') {
    return transformTypescript(src, options)
  }
  return transformEcmascript(src, options ?? {})
}`,
  },
  {
    lang: 'python',
    source: 'psf/requests',
    code: `def prepare_headers(headers):
    result = CaseInsensitiveDict()
    if headers:
        for name, value in headers.items():
            if isinstance(value, bytes):
                value = value.decode('latin1')
            result[to_native_string(name)] = to_native_string(value)
    return result`,
  },
  {
    lang: 'python',
    source: 'pallets/flask',
    code: `def make_response(*args):
    if not args:
        return current_app.response_class()
    if len(args) == 1:
        args = args[0]
    return current_app.make_response(args)`,
  },
  {
    lang: 'python',
    source: 'django/django',
    code: `def get_object_or_404(klass, *args, **kwargs):
    queryset = _get_queryset(klass)
    try:
        return queryset.get(*args, **kwargs)
    except queryset.model.DoesNotExist:
        raise Http404(
            "No %s matches the given query." % queryset.model._meta.object_name
        )`,
  },
  {
    lang: 'python',
    source: 'encode/httpx',
    code: `async def send(self, request: Request, *, stream: bool = False) -> Response:
    response = await self._send_with_response(request)
    if not stream:
        await response.aread()
        await response.aclose()
    return response`,
  },
  {
    lang: 'python',
    source: 'tiangolo/fastapi',
    code: `def get_typed_return_annotation(call: Callable[..., Any]) -> Any:
    hints = get_type_hints(call)
    return hints.get("return")`,
  },
  {
    lang: 'rust',
    source: 'tokio-rs/tokio',
    code: `pub fn spawn<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    Handle::current().spawn(future)
}`,
  },
  {
    lang: 'rust',
    source: 'serde-rs/serde',
    code: `impl<'de> Deserialize<'de> for String {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StringVisitor;
        impl<'de> Visitor<'de> for StringVisitor {
            type Value = String;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<String, E> {
                Ok(v.to_owned())
            }
        }
        deserializer.deserialize_string(StringVisitor)
    }
}`,
  },
  {
    lang: 'rust',
    source: 'actix/actix-web',
    code: `pub async fn extract_path_params<T: DeserializeOwned>(
    req: &HttpRequest,
) -> Result<T, PathError> {
    let params = req.match_info();
    T::deserialize(PathDeserializer::new(params))
        .map_err(|e| PathError::Deserialize(e))
}`,
  },
  {
    lang: 'go',
    source: 'gin-gonic/gin',
    code: `func (c *Context) JSON(code int, obj any) {
	c.Render(code, render.JSON{Data: obj})
}

func (c *Context) Render(code int, r render.Render) {
	c.Status(code)
	if err := r.Render(c.Writer); err != nil {
		panic(err)
	}
}`,
  },
  {
    lang: 'go',
    source: 'golang/go stdlib',
    code: `func ReadAll(r io.Reader) ([]byte, error) {
	b := make([]byte, 0, 512)
	for {
		n, err := r.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return b, err
		}
		if len(b) == cap(b) {
			b = append(b, 0)[:len(b)]
		}
	}
}`,
  },
  {
    lang: 'typescript',
    source: 'effect-ts/effect',
    code: `export const retry = <R, E, A>(
  self: Effect<R, E, A>,
  policy: Schedule<R, E, unknown>,
): Effect<R, E, A> =>
  Effect.flatMap(self, Effect.succeed).pipe(
    Effect.catchAll((e) =>
      Schedule.driver(policy).pipe(
        Effect.flatMap((driver) => retryLoop(self, driver, e)),
      ),
    ),
  )`,
  },
  {
    lang: 'typescript',
    source: 'fp-ts/fp-ts',
    code: `export const pipe = <A>(a: A, ...fns: ReadonlyArray<(a: unknown) => unknown>): unknown => {
  let result: unknown = a
  for (const fn of fns) {
    result = fn(result)
  }
  return result
}`,
  },
  {
    lang: 'typescript',
    source: 'drizzle-team/drizzle',
    code: `export function buildWhereClause(
  table: AnyTable,
  filters: Record<string, unknown>,
): SQL | undefined {
  const conditions = Object.entries(filters).map(([col, val]) =>
    val === null ? isNull(table[col]) : eq(table[col], val),
  )
  return conditions.length === 0 ? undefined : and(...conditions)
}`,
  },
  {
    lang: 'typescript',
    source: 'honojs/hono',
    code: `export class Router<T> {
  private readonly routes: Array<{ path: string; method: string; handler: T }> = []

  add(method: string, path: string, handler: T): void {
    this.routes.push({ path, method, handler })
  }

  match(method: string, path: string): T | undefined {
    return this.routes.find(
      (r) => r.method === method && matchPath(r.path, path),
    )?.handler
  }
}`,
  },
  {
    lang: 'typescript',
    source: 'elysia-dev/elysia',
    code: `export function parseQuery(search: string): Record<string, string> {
  const params = new URLSearchParams(search)
  const result: Record<string, string> = {}
  for (const [key, value] of params.entries()) {
    result[key] = value
  }
  return result
}`,
  },
  {
    lang: 'typescript',
    source: 'elysiajs/eden',
    code: `async function apiFetch<T>(
  url: string,
  init?: RequestInit,
): Promise<{ data: T; error: null } | { data: null; error: Error }> {
  try {
    const response = await fetch(url, init)
    if (!response.ok) throw new Error(\`HTTP \${response.status}\`)
    const data = (await response.json()) as T
    return { data, error: null }
  } catch (e) {
    return { data: null, error: e instanceof Error ? e : new Error(String(e)) }
  }
}`,
  },
  {
    lang: 'typescript',
    source: 'lucia-auth/lucia',
    code: `export async function validateSession(sessionId: string): Promise<Session | null> {
  const session = await adapter.getSession(sessionId)
  if (!session) return null
  if (Date.now() > session.expiresAt.getTime()) {
    await adapter.deleteSession(sessionId)
    return null
  }
  return session
}`,
  },
  {
    lang: 'typescript',
    source: 'supabase/supabase-js',
    code: `export function createClient(supabaseUrl: string, supabaseKey: string): SupabaseClient {
  return new SupabaseClient(supabaseUrl, supabaseKey, {
    auth: { persistSession: true, autoRefreshToken: true },
    realtime: { params: { eventsPerSecond: 10 } },
  })
}`,
  },
  {
    lang: 'typescript',
    source: 'pmndrs/react-spring',
    code: `export function interpolate<In extends readonly number[], Out>(
  inputs: In,
  outputRange: Out[],
  value: number,
): Out {
  const clampedValue = Math.max(inputs[0]!, Math.min(inputs[inputs.length - 1]!, value))
  const index = inputs.findIndex((v, i) => clampedValue >= v && clampedValue <= (inputs[i + 1] ?? Infinity))
  if (index < 0) return outputRange[0]!
  const t = (clampedValue - inputs[index]!) / ((inputs[index + 1] ?? 0) - inputs[index]!)
  return lerp(outputRange[index]!, outputRange[index + 1]!, t)
}`,
  },
  {
    lang: 'typescript',
    source: 'radix-ui/primitives',
    code: `export function composeEventHandlers<E>(
  originalEventHandler?: (event: E) => void,
  ourEventHandler?: (event: E) => void,
  { checkForDefaultPrevented = true } = {},
): (event: E) => void {
  return function handleEvent(event) {
    originalEventHandler?.(event)
    if (checkForDefaultPrevented === false || !(event as unknown as Event).defaultPrevented) {
      ourEventHandler?.(event)
    }
  }
}`,
  },
  {
    lang: 'typescript',
    source: 'ariakit/ariakit',
    code: `export function useId(defaultId?: string): string {
  const [id, setId] = useState(() => defaultId ?? '')
  useEffect(() => {
    if (!id) setId(generateId())
  }, [id])
  return id
}`,
  },
  {
    lang: 'python',
    source: 'pydantic/pydantic',
    code: `def validate_email(value: str) -> str:
    if '@' not in value:
        raise ValueError('Email must contain @')
    local, _, domain = value.rpartition('@')
    if not local or not domain or '.' not in domain:
        raise ValueError('Invalid email format')
    return value.lower()`,
  },
  {
    lang: 'python',
    source: 'sqlalchemy/sqlalchemy',
    code: `def execute_query(session, model_class, filters=None, order_by=None, limit=None):
    query = session.query(model_class)
    if filters:
        query = query.filter(*filters)
    if order_by is not None:
        query = query.order_by(order_by)
    if limit is not None:
        query = query.limit(limit)
    return query.all()`,
  },
  {
    lang: 'python',
    source: 'celery/celery',
    code: `def retry_task(task, exc, countdown=None, max_retries=None):
    retries = task.request.retries
    max_r = max_retries if max_retries is not None else task.max_retries
    if max_r is not None and retries >= max_r:
        raise exc
    raise task.retry(exc=exc, countdown=countdown)`,
  },
  {
    lang: 'typescript',
    source: 'cloudflare/workers-sdk',
    code: `export async function handleCors(
  request: Request,
  allowedOrigins: string[],
): Promise<Response | null> {
  const origin = request.headers.get('Origin')
  if (!origin || !allowedOrigins.includes(origin)) return null
  if (request.method !== 'OPTIONS') return null
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'Access-Control-Max-Age': '86400',
    },
  })
}`,
  },
  {
    lang: 'typescript',
    source: 'graphql/graphql-js',
    code: `export function coerceVariableValues(
  schema: GraphQLSchema,
  varDefNodes: readonly VariableDefinitionNode[],
  inputs: Record<string, unknown>,
): Record<string, unknown> {
  const coercedValues: Record<string, unknown> = {}
  for (const varDefNode of varDefNodes) {
    const varName = varDefNode.variable.name.value
    const varType = typeFromAST(schema, varDefNode.type)
    if (varType === undefined) continue
    const value = inputs[varName]
    coercedValues[varName] = coerceInputValue(value, varType)
  }
  return coercedValues
}`,
  },
  {
    lang: 'typescript',
    source: 'apollographql/apollo-server',
    code: `async function executeOperation(
  requestContext: GraphQLRequestContext,
): Promise<GraphQLResponse> {
  const { request, document, schema } = requestContext
  const executionArgs: ExecutionArgs = {
    schema,
    document,
    variableValues: request.variables,
    contextValue: requestContext.contextValue,
  }
  return execute(executionArgs)
}`,
  },
  {
    lang: 'rust',
    source: 'hyperium/hyper',
    code: `pub async fn serve_connection<I, S>(
    io: I,
    service: S,
) -> Result<(), hyper::Error>
where
    I: AsyncRead + AsyncWrite + Unpin + 'static,
    S: Service<Request<Incoming>>,
    S::Response: Into<Response<BoxBody>>,
{
    let conn = server::conn::http1::Builder::new().serve_connection(io, service);
    conn.await
}`,
  },
  {
    lang: 'go',
    source: 'gorilla/mux',
    code: `func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !r.skipClean {
		path := req.URL.Path
		if r.useEncodedPath {
			path = req.URL.EscapedPath()
		}
		if p := cleanPath(path); p != path {
			url := *req.URL
			url.Path = p
			http.Redirect(w, req, url.String(), http.StatusMovedPermanently)
			return
		}
	}
	r.Match(req, &RouteMatch{}).Handler.ServeHTTP(w, req)
}`,
  },
  {
    lang: 'typescript',
    source: 'oven-sh/bun',
    code: `export async function serve(options: ServeOptions): Promise<Server> {
  const server = Bun.serve({
    port: options.port ?? 3000,
    hostname: options.hostname ?? '0.0.0.0',
    async fetch(req: Request): Promise<Response> {
      const url = new URL(req.url)
      return options.routes[url.pathname]?.(req) ?? new Response('Not Found', { status: 404 })
    },
  })
  return server
}`,
  },
  {
    lang: 'typescript',
    source: 'nodejs/node',
    code: `export function createReadStream(
  path: string | Buffer | URL,
  options?: BufferEncoding | ReadStreamOptions,
): ReadStream {
  return new ReadStream(path, typeof options === 'string' ? { encoding: options } : options)
}`,
  },
  {
    lang: 'python',
    source: 'aio-libs/aiohttp',
    code: `async def fetch_json(session: aiohttp.ClientSession, url: str, **kwargs) -> dict:
    async with session.get(url, **kwargs) as response:
        response.raise_for_status()
        return await response.json()`,
  },
  {
    lang: 'python',
    source: 'encode/starlette',
    code: `class JSONResponse(Response):
    media_type = "application/json"

    def render(self, content: typing.Any) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=None,
            separators=(",", ":"),
        ).encode("utf-8")`,
  },
  {
    lang: 'typescript',
    source: 'nestjs/nest',
    code: `export function Injectable(options?: InjectableOptions): ClassDecorator {
  return (target: object) => {
    Reflect.defineMetadata(INJECTABLE_WATERMARK, true, target)
    Reflect.defineMetadata(SCOPE_OPTIONS_METADATA, options, target)
  }
}`,
  },
  {
    lang: 'typescript',
    source: 'typeorm/typeorm',
    code: `async function findOneBy<Entity>(
  repository: Repository<Entity>,
  where: FindOptionsWhere<Entity>,
): Promise<Entity | null> {
  return repository.findOne({ where })
}`,
  },
  {
    lang: 'typescript',
    source: 'mikro-orm/mikro-orm',
    code: `export function wrap<T extends AnyEntity>(entity: T): IWrappedEntity<T> {
  return entity.__helper as unknown as IWrappedEntity<T>
}`,
  },
]
