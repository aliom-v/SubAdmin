export default function TabNav({ tabs, activeTab, onChange }) {
  return (
    <nav className="tabs">
      {tabs.map((tab) => (
        <button key={tab.id} className={tab.id === activeTab ? 'active' : ''} onClick={() => onChange(tab.id)}>
          {tab.label}
        </button>
      ))}
    </nav>
  )
}
