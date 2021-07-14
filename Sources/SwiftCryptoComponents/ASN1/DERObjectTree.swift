//
//  DERObjectTree.swift
//  
//
//  Created by Pape, Phillip on 7/2/19.
//
//

import Foundation

internal enum DERObjectTree<Element> {
    case empty
    indirect case node(Element, children: [DERObjectTree<Element>])
    indirect case rootNode(children: [DERObjectTree<Element>])
}

extension DERObjectTree {
    func prependChildSubtree(_ subtree: DERObjectTree<Element>) -> DERObjectTree<Element> {
        switch self {
        case .empty:
            return subtree
        case let .node(element, children):
            let newChildren = [subtree] + children
            return .node(element, children: newChildren)
        case let .rootNode(children):
            let newChildren = [subtree] + children
            return .rootNode(children: newChildren)
        }
    }
}

extension DERObjectTree: CustomStringConvertible {
    var description: String {
        switch self {
        case .empty:
            return "()"
        case let .node(element, _):
            return "\(element)"
        case let .rootNode(children):
            return "ROOT:(\(children))"
        }
    }
}

extension DERObjectTree where Element: DERTLVObjectProtocol {
    
    func elementIsOfType(type: DERASN1TypeIdentifier) -> Bool {
        switch self {
        case let .node(elem, _):
            return elem.type == type
        default:
            return false
        }
    }
    
    func valuesForTypeIdentifier(typeId: DERASN1TypeIdentifier) -> [DERTLVValue] {
        
        var relevantValues = [DERTLVValue]()
        
        switch self {
        case .empty:
            break
        case let .node(element, children):
            if element.type == typeId {
                relevantValues.append(element.value)
            }
            relevantValues.append(contentsOf: checkForValues(ofType: typeId, inChildren: children))
        case let .rootNode(children):
            relevantValues.append(contentsOf: checkForValues(ofType: typeId, inChildren: children))
        }
        
        return relevantValues
    }
    
    func checkForValues(ofType typeId: DERASN1TypeIdentifier, inChildren children: [DERObjectTree<Element>]) -> [DERTLVValue] {
        
        var relevantValues = [DERTLVValue]()
        
        for child in children {
            switch child {
            case .empty:
                continue
            case let .node(childElement, grandchildren):
                if childElement.type == typeId {
                    relevantValues.append(childElement.value)
                }
                relevantValues.append(contentsOf: checkForValues(ofType: typeId, inChildren: grandchildren))
            case let .rootNode(rootChildren):
                relevantValues.append(contentsOf: checkForValues(ofType: typeId, inChildren: rootChildren))
            }
        }
        return relevantValues
    }
}
