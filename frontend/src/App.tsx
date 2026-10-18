import { useEffect, useState } from 'react'

type Event = { id: string; ts: string; host: string; type: string; details: Record<string, unknown> }
type Asset = { host: string; criticality: 'low' | 'medium' | 'high' | 'critical' }
type Alert = { rule: string; host: string; severity: 'low' | 'medium' | 'high'; ts: string; event_ids: string[]; summary: string }
type Incident = { id: string; scenario: string; assets: Asset[]; timeline: Event[]; alerts: Alert[]; uncertainties: string[] }

const API = 'http://localhost:8000'
const time = (ts: string) => ts.slice(11, 19)

// Severity is shown by red intensity only: outline < tint < solid.
const sev = {
  low: 'border border-blood/50 text-paper/80',
  medium: 'bg-blood/30 border border-blood text-paper',
  high: 'bg-blood text-paper font-semibold',
}

const Panel = ({ title, children }: { title: string; children: React.ReactNode }) => (
  <section className="rounded-lg border border-paper/15 bg-paper/[0.03] p-5">
    <h2 className="mb-4 text-xs font-semibold uppercase tracking-[0.2em] text-blood">{title}</h2>
    {children}
  </section>
)

export default function App() {
  const [scenarios, setScenarios] = useState<string[]>([])
  const [scenario, setScenario] = useState('ransomware')
  const [inc, setInc] = useState<Incident | null>(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    fetch(`${API}/scenarios`).then(r => r.json()).then(setScenarios).catch(() => setErr('Backend unreachable on :8000'))
  }, [])

  const load = async () => {
    setErr('')
    try {
      const r = await fetch(`${API}/incidents/load?scenario=${scenario}`, { method: 'POST' })
      if (!r.ok) throw new Error(String(r.status))
      setInc(await r.json())
    } catch (e) {
      setErr(`Load failed (${e})`)
    }
  }

  const alerted = new Set(inc?.alerts.flatMap(a => a.event_ids))

  return (
    <main className="mx-auto max-w-6xl px-6 py-10">
      <header className="mb-10 flex flex-wrap items-end justify-between gap-6">
        <div>
          <h1 className="text-4xl font-black tracking-tight">
            Sentinel<span className="bg-gradient-to-r from-blood to-paper bg-clip-text text-transparent">Loop</span>
          </h1>
          <p className="mt-1 text-sm text-paper/60">Evidence → decision → approval → verification</p>
        </div>
        <div className="flex gap-3">
          <select
            value={scenario}
            onChange={e => setScenario(e.target.value)}
            className="rounded-md border border-paper/30 bg-ink px-3 py-2 text-sm text-paper focus:border-blood focus:outline-none"
          >
            {(scenarios.length ? scenarios : [scenario]).map(s => <option key={s}>{s}</option>)}
          </select>
          <button
            onClick={load}
            className="rounded-md bg-gradient-to-r from-blood to-ink px-5 py-2 text-sm font-semibold text-paper ring-1 ring-blood transition hover:from-paper hover:to-blood hover:text-ink"
          >
            Load incident
          </button>
        </div>
      </header>

      {err && <p className="mb-6 border-l-4 border-blood bg-blood/10 px-4 py-2 text-sm">{err}</p>}

      {!inc ? (
        <p className="py-24 text-center text-paper/50">No incident loaded. Pick a scenario and load it.</p>
      ) : (
        <div className="grid gap-6 lg:grid-cols-3">
          <div className="lg:col-span-2">
            <Panel title={`Timeline · ${inc.id}`}>
              <ol className="space-y-2">
                {inc.timeline.map(e => (
                  <li
                    key={e.id}
                    className={`flex gap-4 rounded-md border-l-2 px-3 py-2 text-sm ${alerted.has(e.id) ? 'border-blood bg-blood/10' : 'border-paper/20'}`}
                  >
                    <span className="font-mono text-paper/60">{time(e.ts)}</span>
                    <span className="w-20 font-semibold">{e.host}</span>
                    <span className="text-paper/80">{e.type}</span>
                  </li>
                ))}
              </ol>
            </Panel>
          </div>

          <div className="space-y-6">
            <Panel title="Assets">
              <ul className="space-y-2 text-sm">
                {inc.assets.map(a => (
                  <li key={a.host} className="flex items-center justify-between">
                    <span>{a.host}</span>
                    <span className={`rounded px-2 py-0.5 text-xs uppercase ${a.criticality === 'critical' ? sev.high : sev.low}`}>
                      {a.criticality}
                    </span>
                  </li>
                ))}
              </ul>
            </Panel>

            <Panel title={`Detections · ${inc.alerts.length}`}>
              {inc.alerts.length === 0 ? (
                <p className="text-sm text-paper/50">No detections.</p>
              ) : (
                <ul className="space-y-3 text-sm">
                  {inc.alerts.map((a, i) => (
                    <li key={i}>
                      <span className={`mr-2 rounded px-2 py-0.5 text-xs uppercase ${sev[a.severity]}`}>{a.severity}</span>
                      <span className="font-semibold">{a.host}</span>
                      <p className="mt-1 text-paper/70">{a.summary}</p>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>

            <Panel title="Decision">
              <p className="text-sm text-paper/50">Jev decision, approval and verification arrive in later phases.</p>
            </Panel>
          </div>
        </div>
      )}
    </main>
  )
}
