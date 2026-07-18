import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowLeft,
  BriefcaseBusiness,
  Building2,
  CheckCircle2,
  Database,
  FileKey2,
  Gauge,
  Landmark,
  Link2,
  ListFilter,
  LogOut,
  Menu,
  Network,
  Plus,
  Scale,
  Settings2,
  ShieldCheck,
  Users,
  WalletCards,
  X,
} from "lucide-react";
import { api, type AuthState, type CoreObject, setCsrfToken } from "./api";

type Screen =
  | "dashboard"
  | "fund"
  | "lp"
  | "deal"
  | "ic"
  | "portfolio"
  | "exit"
  | "person"
  | "task"
  | "risk"
  | "fields"
  | "connectors"
  | "audit";

interface SetupStatus {
  setupRequired: boolean;
  network: {
    boundToLoopback: boolean;
    outboundConnectionsEnabledByDefault: boolean;
  };
}

interface Bootstrap {
  account: AuthState["account"];
  counts: Record<string, number>;
  setup: SetupStatus;
}

const modules: Array<{
  id: Screen;
  label: string;
  icon: typeof Gauge;
  permission: string;
  group: string;
}> = [
  { id: "dashboard", label: "Overview", icon: Gauge, permission: "dashboard.view", group: "Workspace" },
  { id: "fund", label: "Funds", icon: Landmark, permission: "fund.view", group: "Portfolio" },
  { id: "lp", label: "Limited partners", icon: WalletCards, permission: "lp.view", group: "Portfolio" },
  { id: "deal", label: "Deal pipeline", icon: BriefcaseBusiness, permission: "deal.view", group: "Investing" },
  { id: "ic", label: "Investment committee", icon: Scale, permission: "ic.view", group: "Investing" },
  { id: "portfolio", label: "Portfolio", icon: Building2, permission: "portfolio.view", group: "Management" },
  { id: "exit", label: "Exits", icon: Activity, permission: "exit.view", group: "Management" },
  { id: "person", label: "People", icon: Users, permission: "person.view", group: "Organization" },
  { id: "task", label: "Tasks", icon: CheckCircle2, permission: "task.view", group: "Organization" },
  { id: "risk", label: "Risk register", icon: ShieldCheck, permission: "risk.view", group: "Organization" },
  { id: "fields", label: "Data structure", icon: Database, permission: "field.view", group: "Administration" },
  { id: "connectors", label: "Connectors", icon: Network, permission: "connector.view", group: "Administration" },
  { id: "audit", label: "Security audit", icon: FileKey2, permission: "audit.view", group: "Administration" },
];

const objectLabels: Record<string, { singular: string; description: string }> = {
  fund: { singular: "fund", description: "Fund mandate, size, deployment, performance and governance." },
  lp: { singular: "limited partner", description: "Commitments, capital calls, distributions and relationship records." },
  deal: { singular: "deal", description: "Sourcing, screening, diligence, committee decisions and transaction progress." },
  ic: { singular: "committee record", description: "Meeting materials, decisions, conditions and voting records." },
  portfolio: { singular: "portfolio record", description: "Operating metrics, reporting, governance and follow-on activity." },
  exit: { singular: "exit record", description: "Exit scenarios, proceeds, distributions and completion status." },
  person: { singular: "person", description: "Internal team, external stakeholders and project responsibilities." },
  task: { singular: "task", description: "Assigned work, deadlines, approvals and completion status." },
  risk: { singular: "risk", description: "Investment, legal, financial, compliance and operational risks." },
};

export function App() {
  const [setup, setSetup] = useState<SetupStatus | null>(null);
  const [auth, setAuth] = useState<AuthState | null>(null);
  const [bootstrap, setBootstrap] = useState<Bootstrap | null>(null);
  const [screen, setScreen] = useState<Screen>("dashboard");
  const [mobileNav, setMobileNav] = useState(false);
  const [error, setError] = useState("");

  const refreshBootstrap = useCallback(async () => {
    const next = await api<Bootstrap>("/api/bootstrap");
    setBootstrap(next);
  }, []);

  useEffect(() => {
    void (async () => {
      try {
        const status = await api<SetupStatus>("/api/setup/status");
        setSetup(status);
        if (!status.setupRequired) {
          const session = await api<AuthState>("/api/auth/me");
          setCsrfToken(session.csrfToken);
          setAuth(session);
          await refreshBootstrap();
        }
      } catch {
        setAuth(null);
      }
    })();
  }, [refreshBootstrap]);

  async function logout() {
    try {
      await api("/api/auth/logout", { method: "POST", body: "{}" });
    } finally {
      setAuth(null);
      setBootstrap(null);
      setCsrfToken("");
    }
  }

  if (!setup) return <LoadingScreen />;
  if (setup.setupRequired) {
    return (
      <SetupScreen
        onComplete={async (next) => {
          setCsrfToken(next.csrfToken);
          setAuth(next);
          setSetup({ ...setup, setupRequired: false });
          await refreshBootstrap();
        }}
      />
    );
  }
  if (!auth) {
    return (
      <LoginScreen
        error={error}
        onLogin={async (email, password) => {
          try {
            setError("");
            const session = await api<AuthState>("/api/auth/login", {
              method: "POST",
              body: JSON.stringify({ email, password }),
            });
            setCsrfToken(session.csrfToken);
            setAuth(session);
            await refreshBootstrap();
          } catch (nextError) {
            setError(nextError instanceof Error ? nextError.message : "Login failed.");
          }
        }}
      />
    );
  }

  const visibleModules = modules.filter((module) =>
    auth.account.permissions.includes(module.permission));
  const grouped = Array.from(new Set(visibleModules.map((module) => module.group)));

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNav ? "open" : ""}`}>
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={19} /></div>
          <div><strong>OpenVC OS</strong><span>Private by default</span></div>
          <button className="icon-button mobile-only" onClick={() => setMobileNav(false)} type="button"><X /></button>
        </div>
        <nav>
          {grouped.map((group) => (
            <div className="nav-group" key={group}>
              <span>{group}</span>
              {visibleModules.filter((module) => module.group === group).map((module) => {
                const Icon = module.icon;
                return (
                  <button
                    className={screen === module.id ? "active" : ""}
                    key={module.id}
                    onClick={() => {
                      setScreen(module.id);
                      setMobileNav(false);
                    }}
                    type="button"
                  >
                    <Icon size={17} />
                    {module.label}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="privacy-state">
          <ShieldCheck size={17} />
          <div>
            <strong>{bootstrap?.setup.network.boundToLoopback ? "Local-only core" : "Network deployment"}</strong>
            <span>No connector is installed</span>
          </div>
        </div>
        <div className="account">
          <div className="avatar">{auth.account.name.slice(0, 1).toUpperCase()}</div>
          <div><strong>{auth.account.name}</strong><span>{auth.account.roles.map((role) => role.name).join(", ")}</span></div>
          <button aria-label="Sign out" className="icon-button" onClick={() => void logout()} title="Sign out" type="button"><LogOut size={16} /></button>
        </div>
      </aside>
      <main>
        <header className="topbar">
          <button className="icon-button mobile-only" onClick={() => setMobileNav(true)} type="button"><Menu /></button>
          <div>
            <span className="eyebrow">OpenVC workspace</span>
            <h1>{modules.find((module) => module.id === screen)?.label}</h1>
          </div>
          <div className="security-chip">
            <ShieldCheck size={15} />
            {bootstrap?.setup.network.boundToLoopback ? "Loopback only" : "Network binding active"}
          </div>
        </header>
        <div className="page">
          {screen === "dashboard" && bootstrap && (
            <Dashboard
              counts={bootstrap.counts}
              onNavigate={setScreen}
              setup={bootstrap.setup}
            />
          )}
          {objectLabels[screen] && (
            <ObjectModule
              canEdit={auth.account.permissions.includes(`${screen}.edit`)}
              label={objectLabels[screen]}
              objectType={screen}
              onChanged={refreshBootstrap}
            />
          )}
          {screen === "fields" && <FieldModule />}
          {screen === "connectors" && <ConnectorModule />}
          {screen === "audit" && <AuditModule />}
        </div>
      </main>
    </div>
  );
}

function LoadingScreen() {
  return <div className="center-screen"><div className="loading-ring" /><p>Opening the encrypted workspace boundary…</p></div>;
}

function SetupScreen({ onComplete }: { onComplete: (auth: AuthState) => Promise<void> }) {
  const [form, setForm] = useState({
    organizationName: "",
    adminName: "",
    email: "",
    password: "",
    setupToken: "",
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  return (
    <AuthLayout title="Create a private workspace" subtitle="No data, account, connector, or external service exists until you create it.">
      <div className="privacy-note"><ShieldCheck size={18} /><span>Initial setup is accepted only from this device. The API listens on loopback by default.</span></div>
      <form onSubmit={(event) => {
        event.preventDefault();
        void (async () => {
          try {
            setBusy(true);
            setError("");
            const result = await api<AuthState>("/api/setup/bootstrap", {
              method: "POST",
              body: JSON.stringify(form),
            });
            await onComplete(result);
          } catch (nextError) {
            setError(nextError instanceof Error ? nextError.message : "Setup failed.");
          } finally {
            setBusy(false);
          }
        })();
      }}>
        <label>Organization<input autoFocus required value={form.organizationName} onChange={(event) => setForm({ ...form, organizationName: event.target.value })} /></label>
        <label>Your name<input required value={form.adminName} onChange={(event) => setForm({ ...form, adminName: event.target.value })} /></label>
        <label>Email<input autoComplete="email" required type="email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} /></label>
        <label>Password<input autoComplete="new-password" minLength={12} required type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} /></label>
        <label>One-time setup token<input autoComplete="off" required value={form.setupToken} onChange={(event) => setForm({ ...form, setupToken: event.target.value })} /></label>
        <small>The API prints this token once in the terminal when the empty workspace starts.</small>
        <small>At least 12 characters with uppercase, lowercase and a number.</small>
        {error && <div className="error">{error}</div>}
        <button className="button primary full" disabled={busy} type="submit">{busy ? "Creating workspace…" : "Create workspace"}</button>
      </form>
    </AuthLayout>
  );
}

function LoginScreen({ error, onLogin }: { error: string; onLogin: (email: string, password: string) => Promise<void> }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <AuthLayout title="Welcome back" subtitle="Sign in to your locally managed VC workspace.">
      <form onSubmit={(event) => {
        event.preventDefault();
        setBusy(true);
        void onLogin(email, password).finally(() => setBusy(false));
      }}>
        <label>Email<input autoComplete="email" autoFocus required type="email" value={email} onChange={(event) => setEmail(event.target.value)} /></label>
        <label>Password<input autoComplete="current-password" required type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
        {error && <div className="error">{error}</div>}
        <button className="button primary full" disabled={busy} type="submit">{busy ? "Signing in…" : "Sign in"}</button>
      </form>
    </AuthLayout>
  );
}

function AuthLayout({ children, title, subtitle }: { children: React.ReactNode; title: string; subtitle: string }) {
  return (
    <div className="auth-screen">
      <section className="auth-intro">
        <div className="brand large"><div className="brand-mark"><ShieldCheck /></div><strong>OpenVC OS</strong></div>
        <h1>Your investment data stays under your control.</h1>
        <p>Local-first storage, explicit permissions, empty connector registry, and no outbound traffic by default.</p>
        <ul>
          <li><ShieldCheck size={17} /> No seeded business data</li>
          <li><Database size={17} /> User-defined data structure</li>
          <li><Network size={17} /> Bring your own connectors</li>
        </ul>
      </section>
      <section className="auth-panel">
        <div><span className="eyebrow">Secure access</span><h2>{title}</h2><p>{subtitle}</p></div>
        {children}
      </section>
    </div>
  );
}

function Dashboard({ counts, onNavigate, setup }: { counts: Record<string, number>; onNavigate: (screen: Screen) => void; setup: SetupStatus }) {
  const total = Object.values(counts).reduce((sum, count) => sum + count, 0);
  return (
    <>
      <section className="page-intro">
        <div><span className="eyebrow">Institution overview</span><h2>A clear starting point, with depth one click away.</h2><p>The first layer stays concise. Open a module to work with its structured records.</p></div>
        <div className="privacy-badge"><ShieldCheck /><div><strong>Privacy boundary active</strong><span>{setup.network.boundToLoopback ? "Local device only" : "Custom network binding"}</span></div></div>
      </section>
      <section className="metric-grid">
        {[
          ["Funds", counts.fund || 0, "fund"],
          ["Active deals", counts.deal || 0, "deal"],
          ["Portfolio records", counts.portfolio || 0, "portfolio"],
          ["Open risks", counts.risk || 0, "risk"],
        ].map(([label, value, target]) => (
          <button className="metric-card" key={String(label)} onClick={() => onNavigate(target as Screen)} type="button">
            <span>{label}</span><strong>{value}</strong><small>Open module</small>
          </button>
        ))}
      </section>
      {total === 0 && (
        <section className="empty-onboarding">
          <div className="empty-icon"><ListFilter /></div>
          <div><h3>Your workspace is intentionally empty</h3><p>Define the fields your organization needs, then add funds, deals, people, and portfolio records. Nothing is imported or synchronized automatically.</p></div>
          <button className="button" onClick={() => onNavigate("fields")} type="button"><Settings2 size={16} /> Define data structure</button>
        </section>
      )}
      <section className="principles">
        <div><ShieldCheck /><h3>Default deny</h3><p>Every API request is authenticated and checked against role permissions.</p></div>
        <div><Database /><h3>Local-first</h3><p>SQLite and uploaded files remain on this device unless an administrator chooses otherwise.</p></div>
        <div><Network /><h3>No silent egress</h3><p>The open core ships without providers, endpoints, credentials, or automatic external calls.</p></div>
      </section>
    </>
  );
}

function ObjectModule({ objectType, label, canEdit, onChanged }: {
  objectType: string;
  label: { singular: string; description: string };
  canEdit: boolean;
  onChanged: () => Promise<void>;
}) {
  const [items, setItems] = useState<CoreObject[]>([]);
  const [selected, setSelected] = useState<CoreObject | null>(null);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    const result = await api<{ items: CoreObject[] }>(`/api/objects/${objectType}`);
    setItems(result.items);
    setSelected((current) => current ? result.items.find((item) => item.id === current.id) || null : null);
  }, [objectType]);

  useEffect(() => { void load(); }, [load]);

  if (selected) {
    return (
      <section className="detail-page">
        <button className="back-button" onClick={() => setSelected(null)} type="button"><ArrowLeft size={16} /> Back to list</button>
        <div className="detail-header"><div><span className="eyebrow">{label.singular}</span><h2>{selected.name}</h2><p>Updated {new Date(selected.updatedAt).toLocaleString()}</p></div><span className="status">{selected.status}</span></div>
        <div className="detail-section"><h3>Core information</h3><div className="field-grid"><div><span>Name</span><strong>{selected.name}</strong></div><div><span>Status</span><strong>{selected.status}</strong></div><div><span>Created</span><strong>{new Date(selected.createdAt).toLocaleDateString()}</strong></div><div><span>Record ID</span><strong className="mono">{selected.id}</strong></div></div></div>
        <div className="detail-section"><h3>Custom fields</h3>{Object.keys(selected.data).length ? <div className="field-grid">{Object.entries(selected.data).map(([key, value]) => <div key={key}><span>{key}</span><strong>{String(value ?? "")}</strong></div>)}</div> : <p className="muted">No custom values have been entered.</p>}</div>
      </section>
    );
  }

  return (
    <>
      <section className="module-header"><div><span className="eyebrow">Structured records</span><h2>{label.singular[0].toUpperCase() + label.singular.slice(1)} workspace</h2><p>{label.description}</p></div>{canEdit && <button className="button primary" onClick={() => setCreating(true)} type="button"><Plus size={16} /> New {label.singular}</button>}</section>
      <section className="list-panel">
        {items.length ? (
          <div className="record-list">
            <div className="record-head"><span>Name</span><span>Status</span><span>Updated</span><span /></div>
            {items.map((item) => (
              <button className="record-row" key={item.id} onClick={() => {
                void api<{ item: CoreObject }>(`/api/objects/${objectType}/${encodeURIComponent(item.id)}`)
                  .then((result) => setSelected(result.item))
                  .catch((nextError) => {
                    setError(nextError instanceof Error ? nextError.message : "Unable to open record.");
                  });
              }} type="button">
                <strong>{item.name}</strong><span><i className="status-dot" />{item.status}</span><span>{new Date(item.updatedAt).toLocaleDateString()}</span><span className="open-link">Open</span>
              </button>
            ))}
          </div>
        ) : (
          <EmptyState message={`No ${label.singular} records exist. The open source edition never seeds or imports data automatically.`} />
        )}
      </section>
      {creating && (
        <Modal title={`New ${label.singular}`} onClose={() => setCreating(false)}>
          <form onSubmit={(event) => {
            event.preventDefault();
            void (async () => {
              try {
                setError("");
                await api(`/api/objects/${objectType}`, { method: "POST", body: JSON.stringify({ name }) });
                setName("");
                setCreating(false);
                await Promise.all([load(), onChanged()]);
              } catch (nextError) {
                setError(nextError instanceof Error ? nextError.message : "Unable to create record.");
              }
            })();
          }}>
            <label>Name<input autoFocus required value={name} onChange={(event) => setName(event.target.value)} /></label>
            {error && <div className="error">{error}</div>}
            <div className="modal-actions"><button className="button" onClick={() => setCreating(false)} type="button">Cancel</button><button className="button primary" type="submit">Create</button></div>
          </form>
        </Modal>
      )}
    </>
  );
}

function FieldModule() {
  const [items, setItems] = useState<Array<Record<string, string | number | boolean>>>([]);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ objectType: "deal", fieldKey: "", label: "", dataType: "text", classification: "internal" });

  const load = useCallback(async () => {
    const result = await api<{ items: Array<Record<string, string | number | boolean>> }>("/api/fields");
    setItems(result.items);
  }, []);
  useEffect(() => { void load(); }, [load]);

  const grouped = useMemo(() => {
    return items.reduce<Record<string, typeof items>>((result, item) => {
      const key = String(item.objectType);
      (result[key] ||= []).push(item);
      return result;
    }, {});
  }, [items]);

  return (
    <>
      <section className="module-header"><div><span className="eyebrow">Schema governance</span><h2>Define your own data structure</h2><p>The repository ships with field types and validation rules, not an institution-specific field catalog.</p></div><button className="button primary" onClick={() => setCreating(true)} type="button"><Plus size={16} /> New field</button></section>
      <section className="list-panel">
        {items.length ? Object.entries(grouped).map(([type, fields]) => <div className="field-group" key={type}><h3>{type}</h3>{fields.map((field) => <div className="field-row" key={String(field.id)}><div><strong>{String(field.label)}</strong><span>{String(field.fieldKey)}</span></div><span>{String(field.dataType)}</span><span className={`classification ${String(field.classification)}`}>{String(field.classification)}</span></div>)}</div>) : <EmptyState message="No fields are defined. Create only the fields your organization needs, or build a separate template package." />}
      </section>
      {creating && <Modal title="New field" onClose={() => setCreating(false)}><form onSubmit={(event) => {
        event.preventDefault();
        void api("/api/fields", { method: "POST", body: JSON.stringify(form) }).then(async () => {
          setCreating(false);
          setForm({ objectType: "deal", fieldKey: "", label: "", dataType: "text", classification: "internal" });
          await load();
        });
      }}><div className="form-grid"><label>Object<select value={form.objectType} onChange={(event) => setForm({ ...form, objectType: event.target.value })}>{Object.keys(objectLabels).map((type) => <option key={type}>{type}</option>)}</select></label><label>Type<select value={form.dataType} onChange={(event) => setForm({ ...form, dataType: event.target.value })}>{["text", "long_text", "number", "currency", "percent", "date", "boolean", "single_select", "multi_select", "relation", "attachment", "url", "email", "formula"].map((type) => <option key={type}>{type}</option>)}</select></label><label>Field key<input pattern="[a-z][a-z0-9_]{1,63}" required value={form.fieldKey} onChange={(event) => setForm({ ...form, fieldKey: event.target.value })} /></label><label>Label<input required value={form.label} onChange={(event) => setForm({ ...form, label: event.target.value })} /></label><label>Classification<select value={form.classification} onChange={(event) => setForm({ ...form, classification: event.target.value })}>{["public", "internal", "restricted", "confidential"].map((value) => <option key={value}>{value}</option>)}</select></label></div><div className="modal-actions"><button className="button" onClick={() => setCreating(false)} type="button">Cancel</button><button className="button primary" type="submit">Create field</button></div></form></Modal>}
    </>
  );
}

function ConnectorModule() {
  const [items, setItems] = useState<Array<{ id: string; name: string; connectorType: string; status: string; configuredSecretCount: number }>>([]);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ name: "", connectorType: "custom" });
  const load = useCallback(async () => setItems((await api<{ items: typeof items }>("/api/connectors")).items), []);
  useEffect(() => { void load(); }, [load]);
  return (
    <>
      <section className="module-header"><div><span className="eyebrow">Explicit integrations</span><h2>Bring your own connector</h2><p>No provider, model, endpoint, MCP server, credential, or external identity service is preinstalled.</p></div><button className="button primary" onClick={() => setCreating(true)} type="button"><Plus size={16} /> Register connector</button></section>
      <div className="privacy-note wide"><ShieldCheck size={18} /><span>Registration stores metadata only. The core does not make outbound calls. Execution belongs in an independently reviewed adapter package.</span></div>
      <section className="list-panel">{items.length ? <div className="connector-list">{items.map((item) => <div className="connector-row" key={item.id}><div className="connector-icon"><Link2 /></div><div><strong>{item.name}</strong><span>{item.connectorType} · {item.configuredSecretCount} encrypted secrets</span></div><span className="status">{item.status}</span></div>)}</div> : <EmptyState message="The connector registry is empty by design." />}</section>
      {creating && <Modal title="Register connector" onClose={() => setCreating(false)}><form onSubmit={(event) => {
        event.preventDefault();
        void api("/api/connectors", { method: "POST", body: JSON.stringify({ ...form, manifest: {} }) }).then(async () => { setCreating(false); setForm({ name: "", connectorType: "custom" }); await load(); });
      }}><label>Name<input autoFocus required value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /></label><label>Connector type<select value={form.connectorType} onChange={(event) => setForm({ ...form, connectorType: event.target.value })}>{["api", "mcp", "data_source", "identity", "storage", "model", "custom"].map((type) => <option key={type}>{type}</option>)}</select></label><div className="modal-actions"><button className="button" onClick={() => setCreating(false)} type="button">Cancel</button><button className="button primary" type="submit">Register disabled connector</button></div></form></Modal>}
    </>
  );
}

function AuditModule() {
  const [items, setItems] = useState<Array<{ id: string; action: string; targetType: string; result: string; createdAt: string }>>([]);
  useEffect(() => { void api<{ items: typeof items }>("/api/audit").then((result) => setItems(result.items)); }, []);
  return (
    <>
      <section className="module-header"><div><span className="eyebrow">Security history</span><h2>Accountable changes</h2><p>Security-relevant actions are recorded locally. Secrets and business payloads are excluded from audit metadata.</p></div></section>
      <section className="list-panel">{items.length ? <div className="audit-list">{items.map((item) => <div className="audit-row" key={item.id}><div className={`audit-result ${item.result}`} /><div><strong>{item.action}</strong><span>{item.targetType}</span></div><time>{new Date(item.createdAt).toLocaleString()}</time></div>)}</div> : <EmptyState message="No audit events are available." />}</section>
    </>
  );
}

function EmptyState({ message }: { message: string }) {
  return <div className="empty-state"><div className="empty-icon"><Database /></div><h3>Nothing here yet</h3><p>{message}</p></div>;
}

function Modal({ children, onClose, title }: { children: React.ReactNode; onClose: () => void; title: string }) {
  return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><section aria-modal="true" className="modal" role="dialog"><header><h2>{title}</h2><button className="icon-button" onClick={onClose} type="button"><X /></button></header>{children}</section></div>;
}
