declare module 'react-cytoscapejs' {
  import { Component } from 'react';
  import * as Cytoscape from 'cytoscape';

  interface CytoscapeComponentProps {
    elements?: Cytoscape.ElementDefinition[];
    style?: React.CSSProperties;
    className?: string;
    layout?: Cytoscape.LayoutOptions;
    stylesheet?: Cytoscape.Stylesheet[];
    cy?: (cy: Cytoscape.Core) => void;
    pan?: Cytoscape.Position;
    zoom?: number;
    minZoom?: number;
    maxZoom?: number;
    autoungrabify?: boolean;
    autounselectify?: boolean;
    boxSelectionEnabled?: boolean;
    wheelSensitivity?: number;
  }

  export default class CytoscapeComponent extends Component<CytoscapeComponentProps> {}
}
