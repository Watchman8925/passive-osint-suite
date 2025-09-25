import React, { useEffect, useState } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Polyline } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';

interface IPPoint {
  ip: string;
  lat: number;
  lon: number;
  asn?: string;
  label?: string;
}

interface FlightRoute {
  flight: string;
  from: { icao: string; lat: number; lon: number; city?: string };
  to: { icao: string; lat: number; lon: number; city?: string };
  path: [number, number][];
  status?: string;
}

interface GeoSnapshot {
  generated_at: string;
  ip_points: IPPoint[];
  flight_routes: FlightRoute[];
  ttl: number;
}

const defaultCenter: [number, number] = [20, 0];

const GeoMap: React.FC = () => {
  const [data, setData] = useState<GeoSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchData() {
      try {
        const res = await fetch('http://localhost:8000/api/geo');
        if (!res.ok) throw new Error('Failed to fetch geo data');
        const json = await res.json();
        if (!cancelled) setData(json);
      } catch (e: any) {
        if (!cancelled) setError(e.message || 'Geo fetch failed');
      }
    }

    fetchData();
    const id = setInterval(fetchData, 60000); // refresh each minute
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  return (
    <div className="w-full h-[600px] rounded-xl overflow-hidden border border-slate-700/50 shadow-lg bg-slate-900/40 backdrop-blur">
      {error && (
        <div className="p-4 text-sm text-red-400">{error}</div>
      )}
      <MapContainer center={defaultCenter} zoom={2} style={{ height: '100%', width: '100%' }} preferCanvas>
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a>'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        {data?.ip_points.map(p => (
          <Marker key={p.ip} position={[p.lat, p.lon]}>
            <Popup>
              <div className="text-sm">
                <div className="font-semibold">{p.label || p.ip}</div>
                <div>{p.ip}</div>
                {p.asn && <div className="text-xs text-slate-500">{p.asn}</div>}
              </div>
            </Popup>
          </Marker>
        ))}
        {data?.flight_routes.map(fr => (
          <React.Fragment key={fr.flight}>
            <Polyline positions={fr.path} pathOptions={{ color: '#6366f1', weight: 3, opacity: 0.7 }} />
            <Marker position={[fr.from.lat, fr.from.lon]}>
              <Popup>
                <div className="text-sm font-semibold">{fr.from.icao} ({fr.from.city})</div>
              </Popup>
            </Marker>
            <Marker position={[fr.to.lat, fr.to.lon]}>
              <Popup>
                <div className="text-sm font-semibold">{fr.to.icao} ({fr.to.city})</div>
              </Popup>
            </Marker>
          </React.Fragment>
        ))}
      </MapContainer>
    </div>
  );
};

export default GeoMap;
