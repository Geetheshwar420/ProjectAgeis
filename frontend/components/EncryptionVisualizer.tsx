import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';

const EncryptionVisualizer: React.FC = () => {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    if (!svgRef.current) return;

    const svg = d3.select(svgRef.current);
    const width = 300;
    const height = 60;

    svg.selectAll('*').remove();

    const data = d3.range(40).map(() => Math.random());
    
    const x = d3.scaleLinear().domain([0, 39]).range([0, width]);
    const y = d3.scaleLinear().domain([0, 1]).range([height, 0]);

    const line = d3.line<number>()
      .x((d, i) => x(i))
      .y(d => y(d))
      .curve(d3.curveBasis);

    const path = svg.append('path')
      .datum(data)
      .attr('fill', 'none')
      .attr('stroke', '#10B981')
      .attr('stroke-width', 2)
      .attr('d', line);

    // Animation
    const animate = () => {
      const newData = d3.range(40).map(() => Math.random() * 0.7 + 0.15);
      
      path.datum(newData)
        .transition()
        .duration(1000)
        .ease(d3.easeLinear)
        .attr('d', line)
        .on('end', animate);
    };

    animate();

  }, []);

  return (
    <div className="w-full h-16 bg-green-900/10 rounded-lg overflow-hidden flex items-center justify-center relative">
        <div className="absolute inset-0 flex items-center justify-center text-xs font-mono text-green-600 font-bold opacity-30 z-0">
            ENCRYPTED SIGNAL
        </div>
      <svg ref={svgRef} width="100%" height="100%" viewBox="0 0 300 60" className="z-10" />
    </div>
  );
};

export default EncryptionVisualizer;