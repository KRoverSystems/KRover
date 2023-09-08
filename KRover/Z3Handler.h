#ifndef _Z3HANDLER_H__
#define _Z3HANDLER_H__

/*class for transfer constraints
 *
 *
*/

#include"z3++.h"
#include "Expr.h"
#include <map>
#include <set>
#include <vector>

typedef EXPR::Expr KVExpr;
typedef std::shared_ptr<KVExpr> KVExprPtr;

using namespace EXPR;
namespace Z3HANDLER {

class Z3Handler{
protected:
    z3::context& context_;
public:

    Z3Handler();
    virtual ~Z3Handler();

    // a set to store symbolic objects
    std::map<VMState::SYMemObject*, z3::expr> symObjectsMap;
    // solver function
    std::map<std::string, unsigned long long> Z3SolveOne(std::set<KVExprPtr> constraints);

    // concritize function (to uint64_t constant)
    z3::expr Z3ExpressionEvaluatorToConstant(z3::expr org_expr, z3::expr, z3::expr);
    uint64_t Z3SolveConcritizeToConstant(std::vector<VMState::SYMemObject*> symobjs,  std::set<KVExprPtr> constraints);
    
    uint64_t Z3ExpressionEvaluatorToConstant2(z3::expr org_expr, z3::expr, z3::expr);
    uint64_t Z3SolveConcritizeToConstant2(std::vector<VMState::SYMemObject*> symobjs,  std::set<KVExprPtr> constraints);

    // concritize function
    z3::expr Z3ExpressionEvaluator(z3::expr org_expr, z3::expr, z3::expr);
    bool Z3SolveConcritize(std::vector<VMState::SYMemObject*> symobjs,  std::set<KVExprPtr> constraints);

    bool Z3ExpressionEvaluator2(z3::expr org_expr, z3::expr, z3::expr);
    bool Z3SolveConcritize2(std::vector<VMState::SYMemObject*> symobjs,  std::set<KVExprPtr> constraints);
    std::set<std::string> ExprToStr(std::set<KVExprPtr> constraints);

    z3::expr Z3HandlingExprPtr(ExprPtr ptr);

    // handle different expressions
    z3::expr Z3HandleUND(ExprPtr undef_expr);

    z3::expr Z3HandleConst(ExprPtr const_expr); // 3
    z3::expr Z3HandleBin(ExprPtr r, ExprPtr l); // not sure how to write z3 expr
    z3::expr Z3HandleTri(ExprPtr r, ExprPtr m, ExprPtr l); // not sure how to write z3 expr
    z3::expr Z3HandleUry(ExprPtr ury_expr); // not sure how to write z3 expr

    z3::expr Z3HandleAdd(ExprPtr r, ExprPtr l); // 7
    z3::expr Z3HandleSub(ExprPtr r, ExprPtr l);
    z3::expr Z3HandleMul(ExprPtr r, ExprPtr l);
    z3::expr Z3HandleUDiv(ExprPtr r, ExprPtr l);

    z3::expr Z3HandleSDiv(ExprPtr r, ExprPtr l); // 11
    z3::expr Z3HandleURem(); // not defined in Exph.h
    z3::expr Z3HandleSRem(ExprPtr r, ExprPtr l);
    z3::expr Z3HandleNeg(ExprPtr neg_expr);
    z3::expr Z3HandleNot(ExprPtr not_expr);
    z3::expr Z3HandleAnd(ExprPtr r, ExprPtr l);
    z3::expr Z3HandleOr(ExprPtr r, ExprPtr l);
    z3::expr Z3HandleXor(ExprPtr r, ExprPtr l);
    z3::expr Z3HandleShl(ExprPtr r, ExprPtr l);
    z3::expr Z3HandleLShr(ExprPtr r, ExprPtr l);

    z3::expr Z3HandleAShr(ExprPtr r, ExprPtr l); // 21
    z3::expr Z3HandleEqual(ExprPtr equal_expr); // should have two sub-expressions?
    z3::expr Z3HandleDistinct(ExprPtr dist_expr); // should have two sub-expressions?
    z3::expr Z3HandleUlt(ExprPtr r, ExprPtr l); // the following comparison only compare with 0?
    z3::expr Z3HandleUle(ExprPtr r, ExprPtr l);
    z3::expr Z3HandleUgt(ExprPtr r, ExprPtr l);
    z3::expr Z3HandleUge(ExprPtr r, ExprPtr l);
    z3::expr Z3HandleSlt(ExprPtr r, ExprPtr l);
    z3::expr Z3HandleSle(ExprPtr r, ExprPtr l);
    z3::expr Z3HandleSgt(ExprPtr r, ExprPtr l);

    z3::expr Z3HandleSge(ExprPtr r, ExprPtr l); // 31
    z3::expr Z3HandleLor(ExprPtr lor_expr); // not defined in Expr.h
    z3::expr Z3HandleLAnd(ExprPtr land_expr); // not defined in Expr.h
    z3::expr Z3HandleLNot(ExprPtr lnot_expr);
    z3::expr Z3HandleSignExt(ExprPtr signext_expr); // different from existing implementation
    z3::expr Z3HandleZeroEXT(ExprPtr zero_expr); // different from existing implmentation
    z3::expr Z3HandleShrd(ExprPtr r, ExprPtr m, ExprPtr l); // not sure how to write z3 expr
    z3::expr Z3HandleSign(ExprPtr sign_expr); // not sure how to write z3 expr
    z3::expr Z3HandleNoSign(ExprPtr nosign_expr); // not sure how to write z3 expr
    z3::expr Z3HandleOverflow(ExprPtr overflow_expr); // not sure how to write z3 expr

    z3::expr Z3HandleNoOverflow(ExprPtr nooverflow_expr); // 41 // not sure how to write z3 expr
    z3::expr Z3HandleCombine(ExprPtr r, ExprPtr l);  // ?lsize? rsize?
    z3::expr Z3HandleExtract(ExprPtr ptr); // need to return size as well
    z3::expr Z3HandleCombineMulti(std::vector<ExprPtr> exprs);

    bool Z3ConstraintChecking(std::set<KVExprPtr> constraints) ;

};
} // end of namespace

#endif  // end of _Z3HANDLER_H__


/* 1. Some expressions are not defined ? e.g., Const? Bin? Tri? Ury?
 * 2. How to define Combine? Tri? Overflow ? Shr ...
 * 3. Some expression are missing? e.g., URem?
 *
*/
