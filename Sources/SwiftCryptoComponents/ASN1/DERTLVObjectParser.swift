//
//  DERTLVObjectParser.swift
//  
//
//  Created by Pape, Phillip on 7/2/19.
//  
//

import Foundation

internal struct DERTLVObjectParser: TLVParser {
    typealias TLVData = Data
    typealias TLVObject = DERTLVObject
    
    func parse(_ data: Data) throws -> (DERTLVObject, Data) {
        
        let typeParser = DERTLVTypeParser()
        let (type, lengthAndValue) = try typeParser.parse(data)
        
        guard type != .endOfContent else {
            return (DERTLVObject.getEndOfContentObject(), Data())
        }
        
        do {
            let lengthParser = DERTLVLengthParser()
            let (length, valueData) = try lengthParser.parse(lengthAndValue)
            let valueParser = DERTLVValueParser(length: length)
            let (value, remainder) = try valueParser.parse(valueData)
            
            let encodingMethod: DERASN1EncodingMethod = (type.rawValue & constructedBitMask != 0) ? .constructed : .primitive
            let object = DERTLVObject(type: type, length: length, value: value, encodingMethod: encodingMethod, objectId: .unparsed)
            
            return (object, remainder)
        } catch {
            return (DERTLVObject.getEndOfContentObject(), Data())
        }
        
    }
}

extension DERTLVObjectParser {
    func parseObjects(_ data: Data) throws -> [DERTLVObject] {
        var objects: [DERTLVObject] = []
        let (object, remainder) = try self.parse(data)
        objects.append(object)
        
        if !remainder.isEmpty {
            objects.append(contentsOf: try parseObjects(remainder))
        }
        if !object.value.isEmpty {
            objects.append(contentsOf: try parseObjects(object.value))
        }
        return objects
    }
    
    func generateTree(_ data: Data) throws -> DERObjectTree<DERTLVObject> {
        let root = DERObjectTree<DERTLVObject>.rootNode(children: [])
        return try self.recurseTree(parent: root, data: data)
    }
    
    private func recurseTree(parent: DERObjectTree<DERTLVObject>, data: Data) throws -> DERObjectTree<DERTLVObject> {
        let (object, remainder) = try self.parse(data)
        var newSubtree = DERObjectTree<DERTLVObject>.node(object, children: [])
        var newParent = parent
        if !remainder.isEmpty {
            // sibling
            newParent = try recurseTree(parent: parent, data: remainder)
        }
        
        if !object.value.isEmpty {
            // child
            newSubtree = try recurseTree(parent: newSubtree, data: object.value)
        }
        
        // insert new subtree as child to trunk
        // prepend b/c w/ recursion this return calls function on final branch 1st
        return newParent.prependChildSubtree(newSubtree)
    }
}
