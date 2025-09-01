import { useState, useEffect, useRef } from 'react';
import { useAppStore } from '../../stores/appStore';
import {
  MagnifyingGlassIcon,
  AdjustmentsHorizontalIcon,
  ArrowsPointingOutIcon,
  ArrowsPointingInIcon,
} from '@heroicons/react/24/outline';
import { HostInfo } from '../../types';

interface NetworkNode {
  id: string;
  label: string;
  ip: string;
  status: 'up' | 'down';
  ports: number;
  x?: number;
  y?: number;
}

interface NetworkEdge {
  from: string;
  to: string;
  type: 'network' | 'connection';
}

export function NetworkMapView() {
  const { scanResults } = useAppStore();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [nodes, setNodes] = useState<NetworkNode[]>([]);
  const [edges, setEdges] = useState<NetworkEdge[]>([]);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [zoomLevel, setZoomLevel] = useState(1);
  const [panOffset, setPanOffset] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  
  // Convert scan results to network topology
  useEffect(() => {
    if (!scanResults?.hosts) {
      setNodes([]);
      setEdges([]);
      return;
    }
    
    const networkNodes: NetworkNode[] = scanResults.hosts.map((host: any, index: number) => {
      const angle = (index / scanResults.hosts.length) * 2 * Math.PI;
      const radius = 200;
      
      return {
        id: host.ip,
        label: host.hostname || host.ip,
        ip: host.ip,
        status: host.status === 'Up' ? 'up' : 'down',
        ports: host.ports?.filter((p: any) => p.state === 'Open').length || 0,
        x: 400 + Math.cos(angle) * radius,
        y: 300 + Math.sin(angle) * radius,
      };
    });
    
    // Create edges based on network relationships
    const networkEdges: NetworkEdge[] = [];
    
    // Group hosts by network (simple subnet detection)
    const networks = new Map<string, string[]>();
    networkNodes.forEach(node => {
      const subnet = node.ip.split('.').slice(0, 3).join('.');
      if (!networks.has(subnet)) {
        networks.set(subnet, []);
      }
      networks.get(subnet)!.push(node.id);
    });
    
    // Create edges within networks
    networks.forEach(hostIds => {
      if (hostIds.length > 1) {
        for (let i = 0; i < hostIds.length - 1; i++) {
          networkEdges.push({
            from: hostIds[i],
            to: hostIds[i + 1],
            type: 'network'
          });
        }
      }
    });
    
    setNodes(networkNodes);
    setEdges(networkEdges);
  }, [scanResults]);
  
  // Canvas drawing
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Apply zoom and pan
    ctx.save();
    ctx.scale(zoomLevel, zoomLevel);
    ctx.translate(panOffset.x, panOffset.y);
    
    // Draw edges
    edges.forEach(edge => {
      const fromNode = nodes.find(n => n.id === edge.from);
      const toNode = nodes.find(n => n.id === edge.to);
      
      if (fromNode && toNode && fromNode.x !== undefined && fromNode.y !== undefined && 
          toNode.x !== undefined && toNode.y !== undefined) {
        ctx.beginPath();
        ctx.moveTo(fromNode.x, fromNode.y);
        ctx.lineTo(toNode.x, toNode.y);
        ctx.strokeStyle = edge.type === 'network' ? '#e5e7eb' : '#3b82f6';
        ctx.lineWidth = edge.type === 'network' ? 1 : 2;
        ctx.stroke();
      }
    });
    
    // Draw nodes
    nodes.forEach(node => {
      if (node.x === undefined || node.y === undefined) return;
      
      const isSelected = selectedNode === node.id;
      const radius = isSelected ? 25 : 20;
      
      // Node circle
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI);
      ctx.fillStyle = node.status === 'up' ? '#10b981' : '#ef4444';
      ctx.fill();
      
      // Node border
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI);
      ctx.strokeStyle = isSelected ? '#3b82f6' : '#ffffff';
      ctx.lineWidth = isSelected ? 3 : 2;
      ctx.stroke();
      
      // Node label
      ctx.fillStyle = '#374151';
      ctx.font = '12px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(node.label, node.x, node.y + radius + 15);
      
      // Port count
      if (node.ports > 0) {
        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 10px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(node.ports.toString(), node.x, node.y + 3);
      }
    });
    
    ctx.restore();
  }, [nodes, edges, selectedNode, zoomLevel, panOffset]);
  
  // Mouse event handlers
  const handleMouseDown = (e: any) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const rect = canvas.getBoundingClientRect();
    const x = (e.clientX - rect.left) / zoomLevel - panOffset.x;
    const y = (e.clientY - rect.top) / zoomLevel - panOffset.y;
    
    // Check if clicking on a node
    const clickedNode = nodes.find(node => {
      if (node.x === undefined || node.y === undefined) return false;
      const distance = Math.sqrt((x - node.x) ** 2 + (y - node.y) ** 2);
      return distance <= 20;
    });
    
    if (clickedNode) {
      setSelectedNode(clickedNode.id);
    } else {
      setSelectedNode(null);
      setIsDragging(true);
      setDragStart({ x: e.clientX - panOffset.x, y: e.clientY - panOffset.y });
    }
  };
  
  const handleMouseMove = (e: any) => {
    if (!isDragging) return;
    
    setPanOffset({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y,
    });
  };
  
  const handleMouseUp = () => {
    setIsDragging(false);
  };
  
  const handleWheel = (e: any) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setZoomLevel(prev => Math.max(0.1, Math.min(3, prev * delta)));
  };
  
  const resetView = () => {
    setZoomLevel(1);
    setPanOffset({ x: 0, y: 0 });
    setSelectedNode(null);
  };
  
  const zoomIn = () => {
    setZoomLevel(prev => Math.min(3, prev * 1.2));
  };
  
  const zoomOut = () => {
    setZoomLevel(prev => Math.max(0.1, prev / 1.2));
  };
  
  const selectedNodeData = selectedNode ? nodes.find(n => n.id === selectedNode) : null;
  const selectedHostData = selectedNode && scanResults?.hosts ? 
    scanResults.hosts.find((h: any) => h.ip === selectedNode) : null;
  
  return (
    <div className="p-6 h-full flex flex-col">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
              Network Map
            </h1>
            <p className="text-gray-600 dark:text-gray-400">
              Visual representation of discovered network topology
            </p>
          </div>
          
          <div className="flex items-center space-x-3">
            <button
              onClick={zoomOut}
              className="p-2 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
              title="Zoom Out"
            >
              <ArrowsPointingInIcon className="h-4 w-4" />
            </button>
            
            <button
              onClick={resetView}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-sm hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
            >
              Reset View
            </button>
            
            <button
              onClick={zoomIn}
              className="p-2 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
              title="Zoom In"
            >
              <ArrowsPointingOutIcon className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>
      
      <div className="flex-1 flex">
        {/* Main Canvas */}
        <div className="flex-1 bg-white dark:bg-gray-800 rounded-lg shadow relative overflow-hidden">
          {nodes.length === 0 ? (
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="text-center">
                <MagnifyingGlassIcon className="mx-auto h-12 w-12 text-gray-400" />
                <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">
                  No network data
                </h3>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                  Run a scan to visualize the network topology.
                </p>
              </div>
            </div>
          ) : (
            <canvas
              ref={canvasRef}
              width={800}
              height={600}
              className="w-full h-full cursor-move"
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
              onMouseLeave={handleMouseUp}
              onWheel={handleWheel}
            />
          )}
          
          {/* Zoom indicator */}
          <div className="absolute bottom-4 left-4 bg-white dark:bg-gray-800 rounded-lg shadow px-3 py-2">
            <span className="text-sm text-gray-600 dark:text-gray-400">
              Zoom: {Math.round(zoomLevel * 100)}%
            </span>
          </div>
        </div>
        
        {/* Side Panel */}
        {selectedNodeData && (
          <div className="w-80 ml-6 bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Host Details
            </h3>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  IP Address
                </label>
                <p className="mt-1 text-sm text-gray-900 dark:text-white">
                  {selectedNodeData.ip}
                </p>
              </div>
              
              {selectedHostData?.hostname && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Hostname
                  </label>
                  <p className="mt-1 text-sm text-gray-900 dark:text-white">
                    {selectedHostData.hostname}
                  </p>
                </div>
              )}
              
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Status
                </label>
                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium mt-1 ${
                  selectedNodeData.status === 'up'
                    ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                    : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                }`}>
                  {selectedNodeData.status === 'up' ? 'Online' : 'Offline'}
                </span>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Open Ports
                </label>
                <p className="mt-1 text-sm text-gray-900 dark:text-white">
                  {selectedNodeData.ports}
                </p>
              </div>
              
              {selectedHostData?.os_fingerprint && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                    Operating System
                  </label>
                  <p className="mt-1 text-sm text-gray-900 dark:text-white">
                    {selectedHostData.os_fingerprint.os_family}
                  </p>
                  {selectedHostData.os_fingerprint.accuracy && (
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      Accuracy: {selectedHostData.os_fingerprint.accuracy}%
                    </p>
                  )}
                </div>
              )}
              
              {selectedHostData?.ports && selectedHostData.ports.length > 0 && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Port Details
                  </label>
                  <div className="space-y-2 max-h-40 overflow-y-auto">
                    {selectedHostData.ports
                      .filter((p: any) => p.state === 'Open')
                      .slice(0, 10)
                      .map((port: any) => (
                        <div key={port.port} className="flex justify-between text-sm">
                          <span className="text-gray-900 dark:text-white">
                            {port.port}/{port.protocol}
                          </span>
                          <span className="text-gray-500 dark:text-gray-400">
                            {port.service?.name || 'Unknown'}
                          </span>
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
      
      {/* Legend */}
      <div className="mt-6 bg-white dark:bg-gray-800 rounded-lg shadow p-4">
        <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-3">
          Legend
        </h4>
        <div className="flex items-center space-x-6">
          <div className="flex items-center space-x-2">
            <div className="w-4 h-4 bg-green-500 rounded-full"></div>
            <span className="text-sm text-gray-600 dark:text-gray-400">Online Host</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-4 h-4 bg-red-500 rounded-full"></div>
            <span className="text-sm text-gray-600 dark:text-gray-400">Offline Host</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-8 h-0.5 bg-gray-300"></div>
            <span className="text-sm text-gray-600 dark:text-gray-400">Network Connection</span>
          </div>
        </div>
      </div>
    </div>
  );
}