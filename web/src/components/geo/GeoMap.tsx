import React, { useEffect, useMemo, useRef, useState } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Polyline } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import { apiClient } from '../../services/apiClient';

interface IPPoint {
  ip: string;
  lat: number;
  lon: number;
  asn?: string;
  label?: string;
  seen_at?: string;
}

interface GeoEndpoint {
  lat: number;
  lon: number;
  label?: string;
  city?: string;
  ip?: string;
  asn?: string;
}

interface FlightRoute {
  flight: string;
  from?: GeoEndpoint;
  to?: GeoEndpoint;
  path: [number, number][];
  status?: string;
}

interface InfrastructureLink {
  id: string;
  from: GeoEndpoint;
  to: GeoEndpoint;
  relationship?: string;
}

interface GeoSnapshot {
  generated_at: string;
  ip_points: IPPoint[];
  flight_routes: FlightRoute[];
  infrastructure_links?: InfrastructureLink[];
  ttl: number;
  next_refresh?: string;
}

const defaultCenter: [number, number] = [20, 0];

const GeoMap: React.FC = () => {
  const [data, setData] = useState<GeoSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const refreshHandle = useRef<number | null>(null);
  const lastTtlRef = useRef<number>(60);

  useEffect(() => {
    let cancelled = false;

    async function fetchData() {
      try {
        const json = await apiClient.get<GeoSnapshot>('/api/geo');
        if (!cancelled) {
          setData(json);
          setError(null);
          const ttlSeconds = Math.max(15, json.ttl || 60);
          lastTtlRef.current = ttlSeconds;
          if (refreshHandle.current) window.clearTimeout(refreshHandle.current);
          refreshHandle.current = window.setTimeout(fetchData, ttlSeconds * 1000);
        }
      } catch (e: any) {
        if (!cancelled) {
          setError(e?.message || 'Geo fetch failed');
          const fallbackTtl = lastTtlRef.current || 60;
          if (refreshHandle.current) window.clearTimeout(refreshHandle.current);
          refreshHandle.current = window.setTimeout(fetchData, fallbackTtl * 1000);
        }
      }
    }

    fetchData();
    return () => {
      cancelled = true;
      if (refreshHandle.current) {
        window.clearTimeout(refreshHandle.current);
      }
    };
  }, []);

  const infrastructureMarkers = useMemo(() => {
    if (!data?.infrastructure_links?.length) return [];
    const seen = new Set(
      (data.ip_points || []).map(point => `${point.lat}:${point.lon}:${point.label ?? ''}`)
    );
    const markers: (GeoEndpoint & { id: string })[] = [];
    data.infrastructure_links.forEach(link => {
      const endpoints: Array<{ node?: GeoEndpoint; key: string }> = [
        { node: link.from, key: `${link.id}:from` },
        { node: link.to, key: `${link.id}:to` },
      ];
      endpoints.forEach(({ node, key }) => {
        if (!node) return;
        const dedupeKey = `${node.lat}:${node.lon}:${node.label ?? node.city ?? ''}`;
        if (seen.has(dedupeKey)) return;
        seen.add(dedupeKey);
        markers.push({ ...node, id: `${link.id}-${key}` });
      });
    });
    return markers;
  }, [data]);

  const hasData = Boolean(
    data?.ip_points?.length || data?.flight_routes?.length || data?.infrastructure_links?.length
  );

  return (
    <div className="w-full h-[600px] rounded-xl overflow-hidden border border-slate-700/50 shadow-lg bg-slate-900/40 backdrop-blur">
      {error && (
        <div className="p-4 text-sm text-red-400">{error}</div>
      )}
      {!error && !hasData && (
        <div className="absolute inset-x-0 top-4 mx-auto max-w-md rounded-md bg-slate-900/80 px-4 py-2 text-center text-sm text-slate-300">
          No recent geospatial activity detected. The map will update automatically when new data
          arrives.
        </div>
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
                {p.seen_at && (
                  <div className="text-xs text-slate-500">Seen: {new Date(p.seen_at).toLocaleString()}</div>
                )}
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
        {data?.infrastructure_links?.map(link => (
          <Polyline
            key={link.id}
            positions={[
              [link.from.lat, link.from.lon],
              [link.to.lat, link.to.lon],
            ]}
            pathOptions={{ color: '#22d3ee', weight: 2, opacity: 0.6, dashArray: '6 4' }}
          />
        ))}
        {infrastructureMarkers.map(point => (
          <Marker key={point.id} position={[point.lat, point.lon]}>
            <Popup>
              <div className="text-sm">
                <div className="font-semibold">{point.label || point.city || 'Infrastructure Node'}</div>
                {point.ip && <div>{point.ip}</div>}
                {point.asn && <div className="text-xs text-slate-500">{point.asn}</div>}
              </div>
            </Popup>
          </Marker>
        ))}
      </MapContainer>
    </div>
  );
};

export default GeoMap;
