import { useMemo } from 'react';

const NODE_TYPE_STYLE = {
  agent: { bg: '#102a3f', border: '#245f84', text: '#6fddff', label: 'agent' },
  tool: { bg: '#113225', border: '#21805a', text: '#73f6b8', label: 'tool' },
  default: { bg: '#1a2132', border: '#3a4a6d', text: '#b7c5df', label: 'node' },
};

const COL_WIDTH = 325;
const ROW_HEIGHT = 138;
const NODE_W = 255;
const NODE_H = 84;
const PAD_X = 54;
const PAD_Y = 50;

function typeStyle(nodeType) {
  return NODE_TYPE_STYLE[nodeType] || NODE_TYPE_STYLE.default;
}

function buildEdges(nodes) {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  return nodes
    .filter((node) => node.parent_id)
    .map((node) => {
      const parent = byId.get(node.parent_id);
      if (!parent) {
        return null;
      }
      return { id: `${parent.id}->${node.id}`, from: parent, to: node };
    })
    .filter(Boolean);
}

function fallbackLayout(nodes, edges) {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const indegree = new Map(nodes.map((node) => [node.id, 0]));
  const outgoing = new Map(nodes.map((node) => [node.id, []]));

  edges.forEach((edge) => {
    indegree.set(edge.to.id, (indegree.get(edge.to.id) || 0) + 1);
    outgoing.get(edge.from.id)?.push(edge.to.id);
  });

  const queue = [];
  indegree.forEach((degree, nodeId) => {
    if (degree === 0) {
      queue.push(nodeId);
    }
  });

  const level = new Map(queue.map((nodeId) => [nodeId, 0]));
  while (queue.length) {
    const current = queue.shift();
    const base = level.get(current) || 0;
    for (const next of outgoing.get(current) || []) {
      level.set(next, Math.max(level.get(next) || 0, base + 1));
      indegree.set(next, (indegree.get(next) || 0) - 1);
      if ((indegree.get(next) || 0) === 0) {
        queue.push(next);
      }
    }
  }

  const groups = new Map();
  nodes.forEach((node) => {
    const col = level.get(node.id) || 0;
    if (!groups.has(col)) {
      groups.set(col, []);
    }
    groups.get(col).push(node.id);
  });

  groups.forEach((ids, col) => {
    ids.forEach((id, row) => {
      const node = byId.get(id);
      if (!node) {
        return;
      }
      node.col = col;
      node.row = row;
    });
  });
}

function normalizeNodes(rawNodes) {
  const nodes = Array.isArray(rawNodes)
    ? rawNodes.map((node, index) => ({
      ...node,
      id: node.id || `node-${index}`,
      name: node.name || node.label || node.id,
      node_type: node.node_type || node.type || 'default',
      row: Number.isFinite(Number(node.row)) ? Number(node.row) : null,
      col: Number.isFinite(Number(node.col)) ? Number(node.col) : null,
    }))
    : [];

  if (!nodes.length) {
    return [];
  }

  const hasExplicitCoords = nodes.every((node) => node.col !== null && node.row !== null);
  if (!hasExplicitCoords) {
    fallbackLayout(nodes, buildEdges(nodes));
  }
  return nodes;
}

function nodePos(node) {
  const x = PAD_X + (node.col || 0) * COL_WIDTH + (COL_WIDTH - NODE_W) / 2;
  const y = PAD_Y + (node.row || 0) * ROW_HEIGHT + (ROW_HEIGHT - NODE_H) / 2;
  return {
    x,
    y,
    right: x + NODE_W,
    left: x,
    midY: y + NODE_H / 2,
  };
}

function edgePath(fromPos, toPos) {
  if (!fromPos || !toPos) {
    return '';
  }
  const startX = fromPos.right;
  const startY = fromPos.midY;
  const endX = toPos.left;
  const endY = toPos.midY;
  const span = Math.max(45, (endX - startX) * 0.45);
  const c1x = startX + span;
  const c2x = endX - span;
  return `M ${startX} ${startY} C ${c1x} ${startY}, ${c2x} ${endY}, ${endX} ${endY}`;
}

export default function AuditGraph({ nodes = [], onNodeSelect, selectedNode }) {
  const layoutNodes = useMemo(() => normalizeNodes(nodes), [nodes]);
  const positions = useMemo(
    () => new Map(layoutNodes.map((node) => [node.id, nodePos(node)])),
    [layoutNodes],
  );

  const edges = useMemo(() => {
    return buildEdges(layoutNodes)
      .map((edge) => ({
        ...edge,
        path: edgePath(positions.get(edge.from.id), positions.get(edge.to.id)),
      }))
      .filter((edge) => Boolean(edge.path));
  }, [layoutNodes, positions]);

  const cols = useMemo(() => Math.max(...layoutNodes.map((node) => node.col || 0), 0) + 1, [layoutNodes]);
  const rows = useMemo(() => Math.max(...layoutNodes.map((node) => node.row || 0), 0) + 1, [layoutNodes]);

  const svgW = cols * COL_WIDTH + PAD_X * 2;
  const svgH = rows * ROW_HEIGHT + PAD_Y * 2;

  if (!layoutNodes.length) {
    return <div className="empty-state">No audit data available.</div>;
  }

  return (
    <div className="audit-graph-wrap">
      <svg width={svgW} height={svgH} style={{ minWidth: svgW }}>
        {edges.map((edge) => (
          <path
            key={edge.id}
            d={edge.path}
            fill="none"
            stroke="#2a4f6d"
            strokeWidth="2"
            strokeOpacity="0.8"
          />
        ))}
        {layoutNodes.map((node) => {
          const pos = positions.get(node.id);
          if (!pos) {
            return null;
          }
          const style = typeStyle(node.node_type);
          const isSelected = selectedNode?.id === node.id;
          const nodeName = String(node.name || node.label || node.id);
          const recordCount = Number(node.record_count ?? 1) || 1;

          return (
            <g key={node.id} onClick={() => onNodeSelect?.(node)} style={{ cursor: 'pointer' }}>
              <rect
                x={pos.x}
                y={pos.y}
                width={NODE_W}
                height={NODE_H}
                rx={14}
                fill={style.bg}
                stroke={isSelected ? '#00d4ff' : style.border}
                strokeWidth={isSelected ? 3 : 1.5}
              />
              {isSelected && (
                <rect
                  x={pos.x}
                  y={pos.y}
                  width={NODE_W}
                  height={NODE_H}
                  rx={14}
                  fill="none"
                  stroke="#00d4ff"
                  strokeWidth="1.5"
                  opacity="0.45"
                />
              )}
              <text x={pos.x + 18} y={pos.y + 34} fill={style.text} fontSize="16" fontFamily="monospace" fontWeight="700">
                {nodeName.length > 22 ? `${nodeName.slice(0, 22)}…` : nodeName}
              </text>
              <text x={pos.x + 18} y={pos.y + 61} fill="#6f86a7" fontSize="11" fontFamily="monospace">
                {style.label}
                {node.worker != null ? ` | W${node.worker}` : ''} | {recordCount} record{recordCount !== 1 ? 's' : ''}
              </text>
              {node.duration_ms != null && (
                <text x={pos.x + NODE_W - 14} y={pos.y + 61} fill="#5f7798" fontSize="10" fontFamily="monospace" textAnchor="end">
                  {node.duration_ms}ms
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
